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
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/version"
)

const (
	managementURL        = "https://api.netbird.internal.codebuckets.in"
	policyURL            = "https://api.netbird.internal.codebuckets.in/client-policy"
	policyPollInterval   = 15 * time.Second
	policyRequestTimeout = 5 * time.Second
	enterpriseRevision   = "codebuckets.1"
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

type connectionMode string

const (
	modeRequired       connectionMode = "REQUIRED"
	modeUserControlled connectionMode = "USER_CONTROLLED"
	modeAdminDisabled  connectionMode = "ADMIN_DISABLED"
)

type policyRequest struct {
	SchemaVersion         int    `json:"schema_version"`
	PeerPublicKey         string `json:"peer_public_key"`
	SystemSerialNumber    string `json:"system_serial_number"`
	Hostname              string `json:"hostname"`
	OS                    string `json:"os"`
	OSVersion             string `json:"os_version"`
	UpstreamVersion       string `json:"upstream_version"`
	EnterpriseRevision    string `json:"enterprise_revision"`
	CurrentPolicyRevision uint64 `json:"current_policy_revision"`
}

type policyResponse struct {
	SchemaVersion  int            `json:"schema_version"`
	Revision       uint64         `json:"revision"`
	PolicyID       string         `json:"policy_id"`
	ConnectionMode connectionMode `json:"connection_mode"`
	IssuedAt       time.Time      `json:"issued_at"`
	ValidUntil     time.Time      `json:"valid_until"`
	ReasonCode     string         `json:"reason_code"`
}

type policyController struct {
	raw           LifecycleServer
	peerPublicKey string
	endpoint      string
	httpClient    *http.Client
	now           func() time.Time

	mu                sync.RWMutex
	snapshot          policyResponse
	hasSnapshot       bool
	lastReconciled    connectionMode
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
		SchemaVersion:         1,
		PeerPublicKey:         p.peerPublicKey,
		SystemSerialNumber:    normalizeSerial(info.SystemSerialNumber),
		Hostname:              info.Hostname,
		OS:                    info.GoOS,
		OSVersion:             info.OSVersion,
		UpstreamVersion:       version.NetbirdVersion(),
		EnterpriseRevision:    enterpriseRevision,
		CurrentPolicyRevision: p.currentRevision(),
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
	if candidate.SchemaVersion != 1 || candidate.Revision == 0 || candidate.PolicyID == "" {
		return errors.New("missing or unsupported policy identity")
	}
	if len(candidate.PolicyID) > 256 || len(candidate.ReasonCode) > 256 {
		return errors.New("policy metadata is too long")
	}
	if candidate.ConnectionMode != modeRequired &&
		candidate.ConnectionMode != modeUserControlled &&
		candidate.ConnectionMode != modeAdminDisabled {
		return fmt.Errorf("unsupported connection mode %q", candidate.ConnectionMode)
	}
	if candidate.IssuedAt.IsZero() || candidate.ValidUntil.IsZero() ||
		candidate.IssuedAt.After(now.Add(maxClockSkew)) || !candidate.ValidUntil.After(now) ||
		!candidate.ValidUntil.After(candidate.IssuedAt) {
		return errors.New("invalid policy validity window")
	}
	if candidate.ConnectionMode == modeUserControlled && candidate.ValidUntil.Sub(now) > maxRelaxationTTL {
		return fmt.Errorf("USER_CONTROLLED exceeds the %s hard TTL", maxRelaxationTTL)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hasSnapshot && candidate.Revision < p.snapshot.Revision {
		return errors.New("policy revision rollback")
	}
	if p.hasSnapshot && candidate.Revision == p.snapshot.Revision && candidate != p.snapshot {
		return errors.New("policy content changed without a revision increment")
	}
	p.snapshot = candidate
	p.hasSnapshot = true
	return nil
}

func (p *policyController) mode(now time.Time) connectionMode {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.hasSnapshot || !p.snapshot.ValidUntil.After(now) {
		return modeRequired
	}
	return p.snapshot.ConnectionMode
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
	mode := p.mode(p.now())
	p.mu.RLock()
	if mode == p.lastReconciled {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	switch mode {
	case modeRequired:
		if _, err := p.raw.Up(ctx, &proto.UpRequest{Async: true}); err != nil {
			log.Warnf("enterprise policy could not converge to REQUIRED: %v", err)
			return
		}
	case modeAdminDisabled:
		if _, err := p.raw.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Warnf("enterprise policy could not converge to ADMIN_DISABLED: %v", err)
			return
		}
	case modeUserControlled:
		// A valid, short-lived relaxation preserves the user's current intent.
	}

	p.mu.Lock()
	p.lastReconciled = mode
	p.mu.Unlock()
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
	errConnectDisabled    = "ENTERPRISE_CONNECT_DISABLED"
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

func (s *wrappedServer) effectiveMode() connectionMode {
	if s.policy == nil {
		return modeRequired
	}
	return s.policy.mode(s.policy.now())
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
	if s.effectiveMode() == modeAdminDisabled {
		return nil, status.Error(codes.PermissionDenied, errConnectDisabled)
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
	if s.effectiveMode() == modeRequired {
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
		response.DisableAutoConnect = false
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
	managed := true
	response.DisableProfiles = true
	response.DisableUpdateSettings = true
	response.DisableNetworks = true
	response.DisableAdvancedView = &managed
	return response, nil
}

func settingsDisabled() error {
	return status.Error(codes.PermissionDenied, errSettingsDisabled)
}

func (s *wrappedServer) SetConfig(context.Context, *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) SelectNetworks(context.Context, *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) DeselectNetworks(context.Context, *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) SetLogLevel(context.Context, *proto.SetLogLevelRequest) (*proto.SetLogLevelResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) CleanState(context.Context, *proto.CleanStateRequest) (*proto.CleanStateResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) DeleteState(context.Context, *proto.DeleteStateRequest) (*proto.DeleteStateResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) SetSyncResponsePersistence(context.Context, *proto.SetSyncResponsePersistenceRequest) (*proto.SetSyncResponsePersistenceResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) SwitchProfile(context.Context, *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) AddProfile(context.Context, *proto.AddProfileRequest) (*proto.AddProfileResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) RenameProfile(context.Context, *proto.RenameProfileRequest) (*proto.RenameProfileResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) RemoveProfile(context.Context, *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) TriggerUpdate(context.Context, *proto.TriggerUpdateRequest) (*proto.TriggerUpdateResponse, error) {
	return nil, settingsDisabled()
}

func (s *wrappedServer) ExposeService(*proto.ExposeServiceRequest, proto.DaemonService_ExposeServiceServer) error {
	return settingsDisabled()
}
