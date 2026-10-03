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
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
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
	policyURL            = "https://api.engineering-fabric.codebuckets.in/api/v1/netbird/client/policy"
	policyPollInterval   = 15 * time.Second
	policyRequestTimeout = 5 * time.Second
)

// enterpriseRevision is not sent on the wire. scripts/overlay.py checks it
// against overlay.config.json so the source and the release revision agree.
const enterpriseRevision = "codebuckets.0"

// LifecycleServer is the narrow seam between NetBird and the enterprise
// decorator. The raw server remains available to the OS service shutdown path.
type LifecycleServer interface {
	proto.DaemonServiceServer
	Start() error
}

const (
	maxPolicyBodyBytes = 64 * 1024
	maxLeaseAhead      = 15 * time.Minute
	policyTokenEnv     = "NB_ENTERPRISE_POLICY_TOKEN"

	// exitNodeV6Suffix names the IPv6 half of an exit node. The daemon hides it
	// from ListNetworks and keeps it in step with its IPv4 base route.
	exitNodeV6Suffix = "-v6"
)

// policyToken is the fleet token every enterprise build presents to the policy
// server. It is never committed: a production build sets it at link time with
//
//	-ldflags "-X github.com/netbirdio/netbird/client/enterprise.policyToken=<token>"
//
// A build without it reads NB_ENTERPRISE_POLICY_TOKEN, which exists for
// development and tests.
var policyToken string

func fleetToken() string {
	if token := strings.TrimSpace(policyToken); token != "" {
		return token
	}
	return strings.TrimSpace(os.Getenv(policyTokenEnv))
}

type exitNodeMode string

const (
	exitNodeDisabled       exitNodeMode = "DISABLED"
	exitNodePinned         exitNodeMode = "PINNED"
	exitNodeUserControlled exitNodeMode = "USER_CONTROLLED"
)

// Enterprise-only control keys. Every other control key is one of NetBird's
// native MDM key names listed in supportedNetBirdControls.
const (
	controlKeepConnected = "keepConnected"
	controlDisableQuit   = "disableQuit"
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
	KeepConnected bool
	DisableQuit   bool
}

type exitNodePolicy struct {
	Mode      exitNodeMode `json:"mode"`
	NetworkID string       `json:"networkId"`
}

type policyRequest struct {
	NetBirdIP    string `json:"netbirdIp"`
	SerialNumber string `json:"serialNumber"`
}

// policyResponse is decoded leniently so the server can extend the contract
// without breaking deployed clients: unknown top-level fields and unknown
// control keys are ignored. A known control that is absent or null resolves to
// its strict default, which is why the values are pointers.
type policyResponse struct {
	PolicyID   string         `json:"policyId"`
	ValidUntil time.Time      `json:"validUntil"`
	Controls   controlSet     `json:"controls"`
	ExitNode   exitNodePolicy `json:"exitNode"`
}

type controlSet map[string]*bool

// UnmarshalJSON keeps a control this build knows only when it is a boolean or
// null, and drops a control it does not know whatever its type. A later server
// can therefore add a control of any shape without this build rejecting the
// whole policy.
func (c *controlSet) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		*c = nil
		return nil
	}
	controls := make(controlSet, len(raw))
	for key, value := range raw {
		var flag *bool
		if err := json.Unmarshal(value, &flag); err != nil {
			if isKnownControl(key) {
				return fmt.Errorf("control %q is not a boolean", key)
			}
			continue
		}
		controls[key] = flag
	}
	*c = controls
	return nil
}

func isKnownControl(key string) bool {
	if key == controlKeepConnected || key == controlDisableQuit {
		return true
	}
	_, native := supportedNetBirdControls[key]
	return native
}

func (r policyResponse) control(key string, strict bool) bool {
	if value := r.Controls[key]; value != nil {
		return *value
	}
	return strict
}

func (r policyResponse) enterpriseControls() enterpriseControls {
	strict := strictEnterpriseControls()
	return enterpriseControls{
		KeepConnected: r.control(controlKeepConnected, strict.KeepConnected),
		DisableQuit:   r.control(controlDisableQuit, strict.DisableQuit),
	}
}

func (r policyResponse) netBirdControls() netBirdControls {
	controls := strictNetBirdControls()
	for key, strict := range controls {
		controls[key] = r.control(key, strict)
	}
	return controls
}

type policyController struct {
	raw        LifecycleServer
	endpoint   string
	httpClient *http.Client
	now        func() time.Time
	updates    *updateGate

	mu                sync.RWMutex
	snapshot          policyResponse
	hasSnapshot       bool
	lastPeerIP        string
	lastFailureLogged time.Time
}

func newPolicyController(raw LifecycleServer, certificate *tls.Certificate) *policyController {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*certificate}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   policyRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("enterprise policy redirects are disabled")
		},
	}
	return &policyController{
		raw:        raw,
		endpoint:   policyURL,
		httpClient: httpClient,
		now:        time.Now,
		updates:    newUpdateGate(version.NetbirdVersion()),
	}
}

func (p *policyController) run(ctx context.Context) {
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
	peerIP := p.netBirdIP(ctx)
	if peerIP == "" {
		// The server resolves the peer by its NetBird IP, so there is nothing
		// to ask for until the peer has one.
		return errors.New("netbird peer is not registered yet")
	}
	info := system.GetInfo(ctx)
	body, err := json.Marshal(policyRequest{
		NetBirdIP:    peerIP,
		SerialNumber: normalizeSerial(info.SystemSerialNumber),
	})
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
	if token := fleetToken(); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := p.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("request policy: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUpgradeRequired {
		// The answer names the build to install and where to get it.
		refusal, _ := io.ReadAll(io.LimitReader(response.Body, maxPolicyBodyBytes))
		p.updates.require(refusal)
		return errors.New("policy server requires a newer enterprise build")
	}
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
	var candidate policyResponse
	if err := decoder.Decode(&candidate); err != nil {
		return fmt.Errorf("decode policy response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	// Measure the lease on the server's clock and anchor it on ours. A wrong
	// local clock then neither rejects a valid policy nor stretches its lease,
	// and in production the anchor carries a monotonic reading, so changing
	// the clock afterwards does not move the expiry either.
	if serverNow, err := http.ParseTime(response.Header.Get("Date")); err == nil {
		candidate.ValidUntil = now.Add(candidate.ValidUntil.Sub(serverNow))
	}
	if err := p.accept(candidate, now); err != nil {
		return fmt.Errorf("reject policy response: %w", err)
	}
	p.updates.clear()
	return nil
}

// netBirdIP returns the local peer's NetBird address without its prefix
// length, or "" when this process has never seen one.
//
// A disconnected daemon reports no local address, but the peer still exists on
// the management server and the policy server identifies it by that address.
// The last address seen is therefore kept: without it a policy that allows
// disconnecting could not be refreshed while disconnected, would expire, and
// the strict default would reconnect the client.
func (p *policyController) netBirdIP(ctx context.Context) string {
	current := p.reportedNetBirdIP(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if current != "" {
		p.lastPeerIP = current
	}
	return p.lastPeerIP
}

func (p *policyController) reportedNetBirdIP(ctx context.Context) string {
	statusCtx, cancel := context.WithTimeout(ctx, policyRequestTimeout)
	defer cancel()
	// The daemon fills LocalPeerState only when the full peer status is requested.
	response, err := p.raw.Status(statusCtx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil || response.GetFullStatus().GetLocalPeerState() == nil {
		return ""
	}
	address := response.GetFullStatus().GetLocalPeerState().GetIP()
	if prefix, err := netip.ParsePrefix(address); err == nil {
		return prefix.Addr().String()
	}
	if ip, err := netip.ParseAddr(address); err == nil {
		return ip.String()
	}
	return ""
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

// accept validates a decoded response and, when valid, makes it the current
// snapshot. A rejected response leaves the previous snapshot in place until
// its own validUntil passes. There is no revision tracking: replay is bounded
// by maxLeaseAhead.
func (p *policyController) accept(candidate policyResponse, now time.Time) error {
	if candidate.PolicyID == "" || len(candidate.PolicyID) > 256 {
		return errors.New("policyId must be 1 to 256 bytes")
	}
	if !candidate.ValidUntil.After(now) {
		return errors.New("validUntil is missing or not in the future")
	}
	if candidate.ValidUntil.Sub(now) > maxLeaseAhead {
		return fmt.Errorf("validUntil is more than %s ahead", maxLeaseAhead)
	}
	if candidate.Controls == nil {
		return errors.New("controls is required")
	}
	if candidate.enterpriseControls().KeepConnected && candidate.netBirdControls()[mdm.KeyDisableAutoConnect] {
		return errors.New("keepConnected conflicts with disableAutoConnect")
	}
	if err := validateExitNode(candidate.ExitNode); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.snapshot = candidate
	p.hasSnapshot = true
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
			return errors.New("PINNED exit-node policy requires networkId")
		}
	case exitNodeDisabled, exitNodeUserControlled:
		if policy.NetworkID != "" {
			return fmt.Errorf("%s exit-node policy must not set networkId", policy.Mode)
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

// effectivePolicy returns the accepted snapshot while its lease is valid.
// Otherwise it returns a policy with no controls and exit nodes disabled, so
// every accessor resolves to the strict defaults.
func (p *policyController) effectivePolicy(now time.Time) policyResponse {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot || !p.snapshot.ValidUntil.After(now) {
		return policyResponse{ExitNode: exitNodePolicy{Mode: exitNodeDisabled}}
	}
	return p.snapshot
}

func (p *policyController) enterpriseControls(now time.Time) enterpriseControls {
	return p.effectivePolicy(now).enterpriseControls()
}

func (p *policyController) netBirdControls(now time.Time) netBirdControls {
	return p.effectivePolicy(now).netBirdControls()
}

func (p *policyController) exitNode(now time.Time) exitNodePolicy {
	return p.effectivePolicy(now).ExitNode
}

func (p *policyController) reconcile(parent context.Context) {
	controls := p.enterpriseControls(p.now())

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if p.updates.requiredVersion() != "" {
		p.disconnectOutdatedBuild(ctx)
		return
	}
	if controls.KeepConnected && p.isIdle(ctx) {
		if _, err := p.raw.Up(ctx, &proto.UpRequest{Async: true}); err != nil {
			log.Warnf("enterprise policy could not converge to keepConnected: %v", err)
		}
	}

	p.reconcileDisableAutoConnect(ctx)
	p.reconcileExitNode(ctx)
}

// disconnectOutdatedBuild takes a build that has been superseded off the
// network. The wrapper refuses to connect it again until it is replaced.
func (p *policyController) disconnectOutdatedBuild(ctx context.Context) {
	response, err := p.raw.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return
	}
	daemonStatus := response.GetStatus()
	if daemonStatus != string(internal.StatusConnected) && daemonStatus != string(internal.StatusConnecting) {
		return
	}
	if _, err := p.raw.Down(ctx, &proto.DownRequest{}); err != nil {
		log.Warnf("enterprise policy could not disconnect an outdated build: %v", err)
	}
}

// isIdle reports whether the daemon is logged in but not connected, which is
// the only state keepConnected acts on. A daemon that is connecting needs
// nothing, and one that needs a login must be left alone: Up in that state
// cancels the sign-in the user has open in the browser.
func (p *policyController) isIdle(ctx context.Context) bool {
	response, err := p.raw.Status(ctx, &proto.StatusRequest{})
	return err == nil && response.GetStatus() == string(internal.StatusIdle)
}

func (p *policyController) reconcileDisableAutoConnect(ctx context.Context) {
	desired := p.netBirdControls(p.now())[mdm.KeyDisableAutoConnect]
	profile, username, err := activeProfile(ctx, p.raw)
	if err != nil {
		log.Debugf("enterprise policy is waiting for the active profile: %v", err)
		return
	}
	config, err := p.raw.GetConfig(ctx, &proto.GetConfigRequest{ProfileName: profile, Username: username})
	if err != nil || config == nil || config.GetDisableAutoConnect() == desired {
		return
	}
	request := &proto.SetConfigRequest{ProfileName: profile, Username: username, DisableAutoConnect: &desired}
	if _, err := p.raw.SetConfig(ctx, request); err != nil {
		log.Warnf("enterprise policy could not apply disableAutoConnect=%t: %v", desired, err)
	}
}

// activeProfile names the profile the daemon is running. The daemon's config
// calls reject an empty profile, so every call the enterprise layer makes or
// locks is addressed to this one.
func activeProfile(ctx context.Context, raw LifecycleServer) (profile, username string, err error) {
	response, err := raw.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		return "", "", fmt.Errorf("get active profile: %w", err)
	}
	profile = response.GetId()
	if profile == "" {
		profile = response.GetProfileName()
	}
	if profile == "" {
		return "", "", errors.New("the daemon reported no active profile")
	}
	return profile, response.GetUsername(), nil
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
	clientCertificate, err := enforceConfiguration(s.configPath)
	if err != nil {
		return fmt.Errorf("enforce enterprise configuration: %w", err)
	}

	if err := s.LifecycleServer.Start(); err != nil {
		return err
	}

	s.policy = newPolicyController(s.LifecycleServer, clientCertificate)
	go s.policy.run(s.rootCtx)
	return nil
}

func enforceConfiguration(configPath string) (*tls.Certificate, error) {
	manager := profilemanager.NewServiceManager(configPath)
	if _, err := manager.CopyDefaultProfileIfNotExists(); err != nil &&
		!errors.Is(err, profilemanager.ErrorOldDefaultConfigNotFound) {
		return nil, fmt.Errorf("migrate default profile: %w", err)
	}

	active, err := manager.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("get active profile: %w", err)
	}
	activePath, err := active.FilePath()
	if err != nil {
		return nil, fmt.Errorf("resolve active profile path: %w", err)
	}

	autoConnectDisabled := false
	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:         activePath,
		ManagementURL:      managementURL,
		DisableAutoConnect: &autoConnectDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("write active profile: %w", err)
	}
	// The daemon stores the URL with its port made explicit, so compare in that form.
	expected, err := profilemanager.ParseServiceURL("Management URL", managementURL)
	if err != nil {
		return nil, fmt.Errorf("parse enterprise management URL: %w", err)
	}
	if config.ManagementURL == nil || config.ManagementURL.String() != expected.String() {
		return nil, fmt.Errorf("management URL was overridden after enterprise enforcement")
	}
	if config.DisableAutoConnect {
		return nil, fmt.Errorf("disable-auto-connect conflicts with enterprise always-on policy")
	}
	return config.ClientCertKeyPair, nil
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

// updateDenial is non-nil while a newer build has been released.
func (s *wrappedServer) updateDenial() error {
	if s.policy == nil {
		return nil
	}
	return s.policy.updates.denial()
}

func (s *wrappedServer) Login(ctx context.Context, request *proto.LoginRequest) (*proto.LoginResponse, error) {
	if err := s.updateDenial(); err != nil {
		return nil, err
	}
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
	if err := s.updateDenial(); err != nil {
		return nil, err
	}
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
	if request.GetProfileName() == "" {
		profile, username, err := activeProfile(ctx, s.LifecycleServer)
		if err != nil {
			return nil, err
		}
		request = &proto.GetConfigRequest{ProfileName: profile, Username: username}
	}
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
	profile, username, err := activeProfile(ctx, s.LifecycleServer)
	if err != nil {
		return nil, err
	}
	lockedRequest := gproto.Clone(request).(*proto.SetConfigRequest)
	lockedRequest.ManagementUrl = managementURL
	lockedRequest.ProfileName = profile
	lockedRequest.Username = username
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
		set[controlDisableQuit] = struct{}{}
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
		if _, isExitNode := exitIDs[strings.TrimSuffix(id, exitNodeV6Suffix)]; isExitNode {
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
