//go:build enterprise

package enterprise

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/version"
)

const (
	managementURL        = "https://api.netbird.internal.codebuckets.in"
	policyURL            = "https://api.netbird.internal.codebuckets.in/client-policy"
	forceDisconnectURL   = "https://api.netbird.internal.codebuckets.in/force-disconnect"
	policyPollInterval   = 15 * time.Second
	policyRequestTimeout = 5 * time.Second
	enterpriseRevision   = "codebuckets.4"
)

// LifecycleServer is the narrow seam between NetBird and the enterprise
// decorator. The raw server remains available to the OS service shutdown path.
type LifecycleServer interface {
	proto.DaemonServiceServer
	Start() error
}

const (
	maxPolicyBodyBytes = 64 * 1024
	maxRelaxationTTL   = 15 * time.Minute
	maxClockSkew       = 5 * time.Minute
	policyTokenEnv     = "NB_ENTERPRISE_POLICY_TOKEN"
)

type exitNodeMode string

const (
	exitNodeDisabled       exitNodeMode = "DISABLED"
	exitNodePinned         exitNodeMode = "PINNED"
	exitNodeUserControlled exitNodeMode = "USER_CONTROLLED"
)

type netBirdControls map[string]bool

var supportedNetBirdControls = map[string]struct{}{
	mdm.KeyDisableUpdateSettings: {},
	mdm.KeyDisableProfiles:       {},
	mdm.KeyDisableNetworks:       {},
	mdm.KeyDisableAdvancedView:   {},
	mdm.KeyDisableAutoConnect:    {},
}

type enterpriseControls struct {
	KeepConnected bool `json:"keepConnected"`
	DisableQuit   bool `json:"disableQuit"`
}

func (c *enterpriseControls) UnmarshalJSON(data []byte) error {
	type wireControls struct {
		KeepConnected *bool `json:"keepConnected"`
		DisableQuit   *bool `json:"disableQuit"`
	}
	var wire wireControls
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if wire.KeepConnected == nil || wire.DisableQuit == nil {
		return errors.New("enterpriseControls requires keepConnected and disableQuit")
	}
	c.KeepConnected = *wire.KeepConnected
	c.DisableQuit = *wire.DisableQuit
	return nil
}

type exitNodePolicy struct {
	Mode      exitNodeMode `json:"mode"`
	NetworkID string       `json:"network_id"`
}

type policyRequest struct {
	SchemaVersion         int           `json:"schema_version"`
	PeerPublicKey         string        `json:"peer_public_key"`
	SystemSerialNumber    string        `json:"system_serial_number"`
	Hostname              string        `json:"hostname"`
	OS                    string        `json:"os"`
	OSVersion             string        `json:"os_version"`
	UpstreamVersion       string        `json:"upstream_version"`
	EnterpriseRevision    string        `json:"enterprise_revision"`
	CurrentPolicyRevision uint64        `json:"current_policy_revision"`
	ExitNodeState         exitNodeState `json:"exit_node_state"`
}

type exitNodeState struct {
	AvailableNetworkIDs []string `json:"available_network_ids"`
	SelectedNetworkIDs  []string `json:"selected_network_ids"`
}

type forceDisconnectRequest struct {
	SchemaVersion      int       `json:"schema_version"`
	PeerPublicKey      string    `json:"peer_public_key"`
	SystemSerialNumber string    `json:"system_serial_number"`
	Hostname           string    `json:"hostname"`
	OS                 string    `json:"os"`
	OSVersion          string    `json:"os_version"`
	UpstreamVersion    string    `json:"upstream_version"`
	EnterpriseRevision string    `json:"enterprise_revision"`
	ReasonCode         string    `json:"reason_code"`
	OccurredAt         time.Time `json:"occurred_at"`
}

type policyResponse struct {
	SchemaVersion      int                `json:"schema_version"`
	Revision           uint64             `json:"revision"`
	PolicyID           string             `json:"policy_id"`
	IssuedAt           time.Time          `json:"issued_at"`
	ValidUntil         time.Time          `json:"valid_until"`
	ReasonCode         string             `json:"reason_code"`
	NetBirdControls    netBirdControls    `json:"netBirdControls"`
	EnterpriseControls enterpriseControls `json:"enterpriseControls"`
	ExitNode            exitNodePolicy     `json:"exit_node"`
}

type policyController struct {
	raw           LifecycleServer
	peerPublicKey string
	endpoint      string
	forceEndpoint string
	httpClient    *http.Client
	now           func() time.Time

	mu                sync.RWMutex
	snapshot          policyResponse
	hasSnapshot       bool
	lastFailureLogged time.Time
}

func newPolicyController(raw LifecycleServer, peerPublicKey string, certificate *tls.Certificate) *policyController {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*certificate}
	}

	return &policyController{
		raw:           raw,
		peerPublicKey: peerPublicKey,
		endpoint:      policyURL,
		forceEndpoint: forceDisconnectURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   policyRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("enterprise policy redirects are disabled")
			},
		},
		now: time.Now,
	}
}

func (p *policyController) run(ctx context.Context) {
	defer p.notifyForceDisconnect()
	p.pollAndReconcile(ctx)
	ticker := time.NewTicker(policyPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.pollAndReconcile(ctx)
		}
	}
}

func (p *policyController) pollAndReconcile(ctx context.Context) {
	if err := p.poll(ctx); err != nil {
		p.logFailure(err)
	}
	p.reconcile(ctx)
}

func (p *policyController) poll(ctx context.Context) error {
	now := p.now()
	info := system.GetInfo(ctx)
	requestPayload := policyRequest{
		SchemaVersion:         4,
		PeerPublicKey:         p.peerPublicKey,
		SystemSerialNumber:    normalizeSerial(info.SystemSerialNumber),
		Hostname:              info.Hostname,
		OS:                    info.GoOS,
		OSVersion:             info.OSVersion,
		UpstreamVersion:       version.NetbirdVersion(),
		EnterpriseRevision:    enterpriseRevision,
		CurrentPolicyRevision: p.currentRevision(),
		ExitNodeState:         p.observeExitNodes(ctx),
	}
	body, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("encode policy request: %w", err)
	}

	requestCtx, cancel := context.WithTimeout(ctx, policyRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create policy request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(os.Getenv(policyTokenEnv)); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := p.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("request policy: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("policy server returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("policy server returned a non-JSON content type")
	}
	limitedBody, err := io.ReadAll(io.LimitReader(response.Body, maxPolicyBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read policy response: %w", err)
	}
	if len(limitedBody) > maxPolicyBodyBytes {
		return fmt.Errorf("policy response exceeds %d bytes", maxPolicyBodyBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(limitedBody))
	decoder.DisallowUnknownFields()
	var candidate policyResponse
	if err := decoder.Decode(&candidate); err != nil {
		return fmt.Errorf("decode policy response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if err := p.accept(candidate, now); err != nil {
		return fmt.Errorf("reject policy response: %w", err)
	}
	return nil
}

func (p *policyController) observeExitNodes(ctx context.Context) exitNodeState {
	state := exitNodeState{
		AvailableNetworkIDs: []string{},
		SelectedNetworkIDs:  []string{},
	}
	response, err := p.raw.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return state
	}
	for _, network := range response.GetRoutes() {
		if network == nil || !isExitNodeRange(network.GetRange()) {
			continue
		}
		state.AvailableNetworkIDs = append(state.AvailableNetworkIDs, network.GetID())
		if network.GetSelected() {
			state.SelectedNetworkIDs = append(state.SelectedNetworkIDs, network.GetID())
		}
	}
	sort.Strings(state.AvailableNetworkIDs)
	sort.Strings(state.SelectedNetworkIDs)
	return state
}

func (p *policyController) notifyForceDisconnect() {
	// The upstream service Stop path waits two seconds after cancelling rootCtx.
	// Keep this best-effort notification inside that graceful shutdown window.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	info := system.GetInfo(ctx)
	payload := forceDisconnectRequest{
		SchemaVersion:      1,
		PeerPublicKey:      p.peerPublicKey,
		SystemSerialNumber: normalizeSerial(info.SystemSerialNumber),
		Hostname:           info.Hostname,
		OS:                 info.GoOS,
		OSVersion:          info.OSVersion,
		UpstreamVersion:    version.NetbirdVersion(),
		EnterpriseRevision: enterpriseRevision,
		ReasonCode:         "CLIENT_SHUTDOWN",
		OccurredAt:         p.now().UTC(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Warnf("enterprise force-disconnect payload failed: %v", err)
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.forceEndpoint, bytes.NewReader(body))
	if err != nil {
		log.Warnf("enterprise force-disconnect request failed: %v", err)
		return
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(os.Getenv(policyTokenEnv)); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		log.Warnf("enterprise force-disconnect notification failed: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		log.Warnf("enterprise force-disconnect notification returned HTTP %d", response.StatusCode)
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("policy response contains multiple JSON values")
		}
		return fmt.Errorf("decode trailing policy data: %w", err)
	}
	return nil
}

func (p *policyController) accept(candidate policyResponse, now time.Time) error {
	if candidate.SchemaVersion != 4 || candidate.Revision == 0 || candidate.PolicyID == "" {
		return errors.New("missing or unsupported policy identity")
	}
	if len(candidate.PolicyID) > 256 || len(candidate.ReasonCode) > 256 {
		return errors.New("policy metadata is too long")
	}
	if err := validateNetBirdControls(candidate.NetBirdControls); err != nil {
		return err
	}
	if err := validateExitNode(candidate.ExitNode); err != nil {
		return err
	}
	if candidate.IssuedAt.IsZero() || candidate.ValidUntil.IsZero() ||
		candidate.IssuedAt.After(now.Add(maxClockSkew)) || !candidate.ValidUntil.After(now) ||
		!candidate.ValidUntil.After(candidate.IssuedAt) {
		return errors.New("invalid policy validity window")
	}
	if candidate.EnterpriseControls.KeepConnected && candidate.NetBirdControls[mdm.KeyDisableAutoConnect] {
		return errors.New("keepConnected conflicts with disableAutoConnect")
	}
	if (!candidate.EnterpriseControls.KeepConnected || !candidate.EnterpriseControls.DisableQuit) &&
		candidate.ValidUntil.Sub(now) > maxRelaxationTTL {
		return fmt.Errorf("enterprise control relaxation exceeds the %s hard TTL", maxRelaxationTTL)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hasSnapshot && candidate.Revision < p.snapshot.Revision {
		return errors.New("policy revision rollback")
	}
	if p.hasSnapshot && candidate.Revision == p.snapshot.Revision && !reflect.DeepEqual(candidate, p.snapshot) {
		return errors.New("policy content changed without a revision increment")
	}
	p.snapshot = candidate
	p.hasSnapshot = true
	return nil
}

func validateNetBirdControls(controls netBirdControls) error {
	if controls == nil {
		return errors.New("netBirdControls is required")
	}
	for name := range controls {
		if _, supported := supportedNetBirdControls[name]; !supported {
			return fmt.Errorf("unsupported NetBird control %q", name)
		}
	}
	return nil
}

func validateExitNode(policy exitNodePolicy) error {
	if policy.NetworkID != strings.TrimSpace(policy.NetworkID) {
		return errors.New("exit-node network ID has surrounding whitespace")
	}
	if len(policy.NetworkID) > 256 {
		return errors.New("exit-node network ID is too long")
	}
	switch policy.Mode {
	case exitNodePinned:
		if policy.NetworkID == "" {
			return errors.New("PINNED exit-node policy requires network_id")
		}
	case exitNodeDisabled, exitNodeUserControlled:
		if policy.NetworkID != "" {
			return fmt.Errorf("%s exit-node policy must not set network_id", policy.Mode)
		}
	default:
		return fmt.Errorf("unsupported exit-node mode %q", policy.Mode)
	}
	return nil
}

func strictNetBirdControls() netBirdControls {
	return netBirdControls{
		mdm.KeyDisableUpdateSettings: true,
		mdm.KeyDisableProfiles:       true,
		mdm.KeyDisableNetworks:       true,
		mdm.KeyDisableAdvancedView:   true,
		mdm.KeyDisableAutoConnect:    false,
	}
}

func strictEnterpriseControls() enterpriseControls {
	return enterpriseControls{KeepConnected: true, DisableQuit: true}
}

func (p *policyController) enterpriseControls(now time.Time) enterpriseControls {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot || !p.snapshot.ValidUntil.After(now) {
		return strictEnterpriseControls()
	}
	return p.snapshot.EnterpriseControls
}

func (p *policyController) netBirdControls(now time.Time) netBirdControls {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot || !p.snapshot.ValidUntil.After(now) {
		return strictNetBirdControls()
	}
	controls := strictNetBirdControls()
	for key, value := range p.snapshot.NetBirdControls {
		controls[key] = value
	}
	return controls
}

func (p *policyController) exitNode(now time.Time) exitNodePolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot || !p.snapshot.ValidUntil.After(now) {
		return exitNodePolicy{Mode: exitNodeDisabled}
	}
	return p.snapshot.ExitNode
}

func (p *policyController) currentRevision() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot {
		return 0
	}
	return p.snapshot.Revision
}

func (p *policyController) reconcile(parent context.Context) {
	controls := p.enterpriseControls(p.now())

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if controls.KeepConnected && !p.isConnectedOrConnecting(ctx) {
		if _, err := p.raw.Up(ctx, &proto.UpRequest{Async: true}); err != nil {
			log.Warnf("enterprise policy could not converge to keepConnected: %v", err)
		}
	}

	p.reconcileDisableAutoConnect(ctx)
	p.reconcileExitNode(ctx)
}

func (p *policyController) isConnectedOrConnecting(ctx context.Context) bool {
	response, err := p.raw.Status(ctx, &proto.StatusRequest{})
	if err != nil || response == nil {
		return false
	}
	return response.GetStatus() == string(internal.StatusConnected) ||
		response.GetStatus() == string(internal.StatusConnecting)
}

func (p *policyController) reconcileDisableAutoConnect(ctx context.Context) {
	desired := p.netBirdControls(p.now())[mdm.KeyDisableAutoConnect]
	config, err := p.raw.GetConfig(ctx, &proto.GetConfigRequest{})
	if err != nil || config == nil || config.GetDisableAutoConnect() == desired {
		return
	}
	if _, err := p.raw.SetConfig(ctx, &proto.SetConfigRequest{DisableAutoConnect: &desired}); err != nil {
		log.Warnf("enterprise policy could not apply disableAutoConnect=%t: %v", desired, err)
	}
}

func (p *policyController) reconcileExitNode(ctx context.Context) {
	policy := p.exitNode(p.now())
	if policy.Mode == exitNodeUserControlled {
		return
	}

	response, err := p.raw.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		log.Debugf("enterprise exit-node policy is waiting for routes: %v", err)
		return
	}

	var selectedExitNodes []string
	targetAvailable := false
	for _, network := range response.GetRoutes() {
		if network == nil || !isExitNodeRange(network.GetRange()) {
			continue
		}
		if network.GetSelected() {
			selectedExitNodes = append(selectedExitNodes, network.GetID())
		}
		if network.GetID() == policy.NetworkID {
			targetAvailable = true
		}
	}

	if policy.Mode == exitNodePinned && targetAvailable {
		if len(selectedExitNodes) == 1 && selectedExitNodes[0] == policy.NetworkID {
			return
		}
		_, err = p.raw.SelectNetworks(ctx, &proto.SelectNetworksRequest{
			NetworkIDs: []string{policy.NetworkID},
			Append:     true,
		})
		if err != nil {
			log.Warnf("enterprise policy could not pin exit node %q: %v", policy.NetworkID, err)
		}
		return
	}

	if len(selectedExitNodes) > 0 {
		if _, err := p.raw.DeselectNetworks(ctx, &proto.SelectNetworksRequest{NetworkIDs: selectedExitNodes}); err != nil {
			log.Warnf("enterprise policy could not disable exit nodes: %v", err)
			return
		}
	}
	if policy.Mode == exitNodePinned && !targetAvailable {
		log.Warnf("enterprise pinned exit node %q is not available; all exit nodes remain disabled", policy.NetworkID)
	}
}

func isExitNodeRange(value string) bool {
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err == nil && prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func (p *policyController) logFailure(err error) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Sub(p.lastFailureLogged) < time.Minute {
		return
	}
	p.lastFailureLogged = now
	log.Warnf("enterprise policy poll failed; retaining fail-closed mode: %v", err)
}

func normalizeSerial(value string) string {
	value = strings.Trim(value, "\x00 \t\r\n")
	if utf8.RuneCountInString(value) <= 256 {
		return value
	}
	runes := []rune(value)
	return string(runes[:256])
}

const (
	errDisconnectDisabled = "ENTERPRISE_DISCONNECT_DISABLED"
	errLogoutDisabled     = "ENTERPRISE_LOGOUT_DISABLED"
	errSettingsDisabled   = "ENTERPRISE_SETTINGS_DISABLED"
)

type wrappedServer struct {
	LifecycleServer
	rootCtx    context.Context
	configPath string
	policy     *policyController
}

// Wrap is the sole enterprise composition hook in upstream NetBird code.
func Wrap(ctx context.Context, raw LifecycleServer, configPath string) LifecycleServer {
	return &wrappedServer{
		LifecycleServer: raw,
		rootCtx:         ctx,
		configPath:      configPath,
	}
}

func (s *wrappedServer) Start() error {
	peerPublicKey, clientCertificate, err := enforceConfiguration(s.configPath)
	if err != nil {
		return fmt.Errorf("enforce enterprise configuration: %w", err)
	}

	if err := s.LifecycleServer.Start(); err != nil {
		return err
	}

	s.policy = newPolicyController(s.LifecycleServer, peerPublicKey, clientCertificate)
	go s.policy.run(s.rootCtx)
	return nil
}

func enforceConfiguration(configPath string) (string, *tls.Certificate, error) {
	manager := profilemanager.NewServiceManager(configPath)
	if _, err := manager.CopyDefaultProfileIfNotExists(); err != nil &&
		!errors.Is(err, profilemanager.ErrorOldDefaultConfigNotFound) {
		return "", nil, fmt.Errorf("migrate default profile: %w", err)
	}

	active, err := manager.GetActiveProfileState()
	if err != nil {
		return "", nil, fmt.Errorf("get active profile: %w", err)
	}
	activePath, err := active.FilePath()
	if err != nil {
		return "", nil, fmt.Errorf("resolve active profile path: %w", err)
	}

	autoConnectDisabled := false
	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:         activePath,
		ManagementURL:      managementURL,
		DisableAutoConnect: &autoConnectDisabled,
	})
	if err != nil {
		return "", nil, fmt.Errorf("write active profile: %w", err)
	}
	if config.ManagementURL == nil ||
		config.ManagementURL.String() != managementURL {
		return "", nil, fmt.Errorf("management URL was overridden after enterprise enforcement")
	}
	if config.DisableAutoConnect {
		return "", nil, fmt.Errorf("disable-auto-connect conflicts with enterprise always-on policy")
	}

	privateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("parse peer identity: %w", err)
	}
	return privateKey.PublicKey().String(), config.ClientCertKeyPair, nil
}

func (s *wrappedServer) effectiveEnterpriseControls() enterpriseControls {
	if s.policy == nil {
		return strictEnterpriseControls()
	}
	return s.policy.enterpriseControls(s.policy.now())
}

func (s *wrappedServer) netBirdControl(key string) bool {
	if s.policy == nil {
		return strictNetBirdControls()[key]
	}
	return s.policy.netBirdControls(s.policy.now())[key]
}

func (s *wrappedServer) effectiveExitNode() exitNodePolicy {
	if s.policy == nil {
		return exitNodePolicy{Mode: exitNodeDisabled}
	}
	return s.policy.exitNode(s.policy.now())
}

func (s *wrappedServer) Login(ctx context.Context, request *proto.LoginRequest) (*proto.LoginResponse, error) {
	if request == nil {
		request = &proto.LoginRequest{}
	}
	lockedRequest := gproto.Clone(request).(*proto.LoginRequest)
	lockedRequest.ManagementUrl = managementURL
	lockedRequest.ProfileName = nil
	lockedRequest.Username = nil
	return s.LifecycleServer.Login(ctx, lockedRequest)
}

func (s *wrappedServer) Up(ctx context.Context, request *proto.UpRequest) (*proto.UpResponse, error) {
	if request == nil {
		request = &proto.UpRequest{}
	}
	lockedRequest := gproto.Clone(request).(*proto.UpRequest)
	lockedRequest.ProfileName = nil
	lockedRequest.Username = nil
	return s.LifecycleServer.Up(ctx, lockedRequest)
}

func (s *wrappedServer) Down(ctx context.Context, request *proto.DownRequest) (*proto.DownResponse, error) {
	if s.effectiveEnterpriseControls().KeepConnected {
		return nil, status.Error(codes.PermissionDenied, errDisconnectDisabled)
	}
	return s.LifecycleServer.Down(ctx, request)
}

func (s *wrappedServer) Logout(context.Context, *proto.LogoutRequest) (*proto.LogoutResponse, error) {
	return nil, status.Error(codes.PermissionDenied, errLogoutDisabled)
}

func (s *wrappedServer) GetConfig(ctx context.Context, request *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	response, err := s.LifecycleServer.GetConfig(ctx, request)
	if err == nil && response != nil {
		response.ManagementUrl = managementURL
		response.DisableAutoConnect = s.netBirdControl(mdm.KeyDisableAutoConnect)
		response.MDMManagedFields = s.enterpriseManagedFields(response.GetMDMManagedFields())
	}
	return response, err
}

func (s *wrappedServer) GetFeatures(ctx context.Context, request *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	response, err := s.LifecycleServer.GetFeatures(ctx, request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		response = &proto.GetFeaturesResponse{}
	}
	response.DisableProfiles = response.DisableProfiles || s.netBirdControl(mdm.KeyDisableProfiles)
	response.DisableUpdateSettings = response.DisableUpdateSettings || s.netBirdControl(mdm.KeyDisableUpdateSettings)
	response.DisableNetworks = response.DisableNetworks || s.netBirdControl(mdm.KeyDisableNetworks)
	advancedViewDisabled := s.netBirdControl(mdm.KeyDisableAdvancedView)
	if response.DisableAdvancedView != nil {
		advancedViewDisabled = advancedViewDisabled || response.GetDisableAdvancedView()
	}
	response.DisableAdvancedView = &advancedViewDisabled
	return response, nil
}

func settingsDisabled() error {
	return status.Error(codes.PermissionDenied, errSettingsDisabled)
}

func (s *wrappedServer) SetConfig(ctx context.Context, request *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return nil, settingsDisabled()
	}
	if request == nil {
		request = &proto.SetConfigRequest{}
	}
	lockedRequest := gproto.Clone(request).(*proto.SetConfigRequest)
	lockedRequest.ManagementUrl = managementURL
	lockedRequest.ProfileName = ""
	lockedRequest.Username = ""
	disableAutoConnect := s.netBirdControl(mdm.KeyDisableAutoConnect)
	lockedRequest.DisableAutoConnect = &disableAutoConnect
	return s.LifecycleServer.SetConfig(ctx, lockedRequest)
}

func (s *wrappedServer) enterpriseManagedFields(existing []string) []string {
	set := make(map[string]struct{}, len(existing)+len(supportedNetBirdControls)+2)
	for _, key := range existing {
		set[key] = struct{}{}
	}
	set[mdm.KeyManagementURL] = struct{}{}
	for key := range supportedNetBirdControls {
		set[key] = struct{}{}
	}
	if s.effectiveEnterpriseControls().DisableQuit {
		set["disableQuit"] = struct{}{}
	}
	managed := make([]string, 0, len(set))
	for key := range set {
		managed = append(managed, key)
	}
	sort.Strings(managed)
	return managed
}

func (s *wrappedServer) SelectNetworks(ctx context.Context, request *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	if s.netBirdControl(mdm.KeyDisableNetworks) {
		return nil, settingsDisabled()
	}
	if err := s.rejectManagedExitNodeMutation(ctx, request, true); err != nil {
		return nil, err
	}
	return s.LifecycleServer.SelectNetworks(ctx, request)
}

func (s *wrappedServer) DeselectNetworks(ctx context.Context, request *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	if s.netBirdControl(mdm.KeyDisableNetworks) {
		return nil, settingsDisabled()
	}
	if err := s.rejectManagedExitNodeMutation(ctx, request, false); err != nil {
		return nil, err
	}
	return s.LifecycleServer.DeselectNetworks(ctx, request)
}

func (s *wrappedServer) rejectManagedExitNodeMutation(ctx context.Context, request *proto.SelectNetworksRequest, selecting bool) error {
	if s.effectiveExitNode().Mode == exitNodeUserControlled {
		return nil
	}
	if request == nil || request.GetAll() || (selecting && !request.GetAppend()) {
		return settingsDisabled()
	}
	networks, err := s.LifecycleServer.ListNetworks(ctx, &proto.ListNetworksRequest{})
	if err != nil {
		return settingsDisabled()
	}
	exitIDs := make(map[string]struct{})
	for _, network := range networks.GetRoutes() {
		if network != nil && isExitNodeRange(network.GetRange()) {
			exitIDs[network.GetID()] = struct{}{}
		}
	}
	for _, id := range request.GetNetworkIDs() {
		if _, isExitNode := exitIDs[id]; isExitNode {
			return settingsDisabled()
		}
	}
	return nil
}

func (s *wrappedServer) SetLogLevel(ctx context.Context, request *proto.SetLogLevelRequest) (*proto.SetLogLevelResponse, error) {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.SetLogLevel(ctx, request)
}

func (s *wrappedServer) CleanState(ctx context.Context, request *proto.CleanStateRequest) (*proto.CleanStateResponse, error) {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.CleanState(ctx, request)
}

func (s *wrappedServer) DeleteState(ctx context.Context, request *proto.DeleteStateRequest) (*proto.DeleteStateResponse, error) {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.DeleteState(ctx, request)
}

func (s *wrappedServer) SetSyncResponsePersistence(ctx context.Context, request *proto.SetSyncResponsePersistenceRequest) (*proto.SetSyncResponsePersistenceResponse, error) {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.SetSyncResponsePersistence(ctx, request)
}

func (s *wrappedServer) SwitchProfile(ctx context.Context, request *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	if s.netBirdControl(mdm.KeyDisableProfiles) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.SwitchProfile(ctx, request)
}

func (s *wrappedServer) AddProfile(ctx context.Context, request *proto.AddProfileRequest) (*proto.AddProfileResponse, error) {
	if s.netBirdControl(mdm.KeyDisableProfiles) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.AddProfile(ctx, request)
}

func (s *wrappedServer) RenameProfile(ctx context.Context, request *proto.RenameProfileRequest) (*proto.RenameProfileResponse, error) {
	if s.netBirdControl(mdm.KeyDisableProfiles) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.RenameProfile(ctx, request)
}

func (s *wrappedServer) RemoveProfile(ctx context.Context, request *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	if s.netBirdControl(mdm.KeyDisableProfiles) {
		return nil, settingsDisabled()
	}
	return s.LifecycleServer.RemoveProfile(ctx, request)
}

func (s *wrappedServer) TriggerUpdate(context.Context, *proto.TriggerUpdateRequest) (*proto.TriggerUpdateResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) ExposeService(request *proto.ExposeServiceRequest, stream proto.DaemonService_ExposeServiceServer) error {
	if s.netBirdControl(mdm.KeyDisableUpdateSettings) {
		return settingsDisabled()
	}
	return s.LifecycleServer.ExposeService(request, stream)
}
