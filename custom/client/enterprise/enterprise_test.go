//go:build enterprise

package enterprise

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

type fakeLifecycleServer struct {
	proto.UnimplementedDaemonServiceServer
	upCalls           int
	downCalls         int
	logoutCalls       int
	switchProfileCalls int
	status            string
	features          *proto.GetFeaturesResponse
	config            *proto.GetConfigResponse
	networks          []*proto.Network
	loginRequests     []*proto.LoginRequest
	selectRequests    []*proto.SelectNetworksRequest
	deselectRequests  []*proto.SelectNetworksRequest
	setConfigRequests []*proto.SetConfigRequest
}

func (*fakeLifecycleServer) Start() error {
	return nil
}

func (f *fakeLifecycleServer) Up(context.Context, *proto.UpRequest) (*proto.UpResponse, error) {
	f.upCalls++
	return &proto.UpResponse{}, nil
}

func (f *fakeLifecycleServer) Down(context.Context, *proto.DownRequest) (*proto.DownResponse, error) {
	f.downCalls++
	return &proto.DownResponse{}, nil
}

func (f *fakeLifecycleServer) Logout(context.Context, *proto.LogoutRequest) (*proto.LogoutResponse, error) {
	f.logoutCalls++
	return &proto.LogoutResponse{}, nil
}

func (f *fakeLifecycleServer) Login(_ context.Context, request *proto.LoginRequest) (*proto.LoginResponse, error) {
	f.loginRequests = append(f.loginRequests, request)
	return &proto.LoginResponse{}, nil
}

func (f *fakeLifecycleServer) Status(context.Context, *proto.StatusRequest) (*proto.StatusResponse, error) {
	return &proto.StatusResponse{Status: f.status}, nil
}

func (f *fakeLifecycleServer) SwitchProfile(context.Context, *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	f.switchProfileCalls++
	return &proto.SwitchProfileResponse{}, nil
}

func (f *fakeLifecycleServer) ListNetworks(context.Context, *proto.ListNetworksRequest) (*proto.ListNetworksResponse, error) {
	return &proto.ListNetworksResponse{Routes: f.networks}, nil
}

func (f *fakeLifecycleServer) SelectNetworks(_ context.Context, request *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	f.selectRequests = append(f.selectRequests, request)
	return &proto.SelectNetworksResponse{}, nil
}

func (f *fakeLifecycleServer) DeselectNetworks(_ context.Context, request *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	f.deselectRequests = append(f.deselectRequests, request)
	return &proto.SelectNetworksResponse{}, nil
}

func (f *fakeLifecycleServer) GetFeatures(context.Context, *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	if f.features == nil {
		return &proto.GetFeaturesResponse{}, nil
	}
	return f.features, nil
}

func (f *fakeLifecycleServer) GetConfig(context.Context, *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	if f.config == nil {
		return &proto.GetConfigResponse{}, nil
	}
	return f.config, nil
}

func (f *fakeLifecycleServer) SetConfig(_ context.Context, request *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	f.setConfigRequests = append(f.setConfigRequests, request)
	if request.GetDisableAutoConnect() && f.config != nil {
		f.config.DisableAutoConnect = true
	}
	return &proto.SetConfigResponse{}, nil
}

func TestPolicyPollUsesJSONAndIncludesSerialField(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestReceived = true
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want application/json", request.Header.Get("Accept"))
		}
		if request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", request.Header.Get("Content-Type"))
		}

		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := payload["system_serial_number"]; !ok {
			t.Error("request does not contain system_serial_number")
		}
		if payload["peer_public_key"] != "test-peer-key" {
			t.Errorf("peer_public_key = %v, want test-peer-key", payload["peer_public_key"])
		}
		if payload["schema_version"] != float64(4) {
			t.Errorf("schema_version = %v, want 4", payload["schema_version"])
		}
		if _, ok := payload["exit_node_state"]; !ok {
			t.Error("request does not contain exit_node_state")
		}

		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(policyResponse{
			SchemaVersion:      4,
			Revision:           1,
			PolicyID:           "test-policy",
			IssuedAt:           fixedNow.Add(-time.Minute),
			ValidUntil:         fixedNow.Add(time.Minute),
			ReasonCode:         "TEST",
			NetBirdControls:    strictNetBirdControls(),
			EnterpriseControls: enterpriseControls{KeepConnected: true, DisableQuit: true},
			ExitNode:            exitNodePolicy{Mode: exitNodeDisabled},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	t.Setenv(policyTokenEnv, "")
	controller := newPolicyController(&fakeLifecycleServer{}, "test-peer-key", nil)
	controller.endpoint = server.URL
	controller.now = func() time.Time { return fixedNow }

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !requestReceived {
		t.Fatal("policy server did not receive a request")
	}
	if got := controller.enterpriseControls(fixedNow); !got.KeepConnected || !got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want strict controls", got)
	}
	if policyPollInterval != 15*time.Second {
		t.Fatalf("poll interval = %s, want 15s", policyPollInterval)
	}
}

func TestPolicyIsFailClosedAndRejectsRollback(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controller := &policyController{now: func() time.Time { return fixedNow }}
	valid := policyResponse{
		SchemaVersion:      4,
		Revision:           2,
		PolicyID:           "support-window",
		IssuedAt:           fixedNow.Add(-time.Minute),
		ValidUntil:         fixedNow.Add(time.Minute),
		NetBirdControls:    strictNetBirdControls(),
		EnterpriseControls: enterpriseControls{KeepConnected: false, DisableQuit: false},
		ExitNode:            exitNodePolicy{Mode: exitNodeDisabled},
	}
	if err := controller.accept(valid, fixedNow); err != nil {
		t.Fatalf("accept valid policy: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); got.KeepConnected || got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want valid relaxation", got)
	}
	if got := controller.enterpriseControls(valid.ValidUntil); !got.KeepConnected || !got.DisableQuit {
		t.Fatalf("expired controls = %+v, want strict controls", got)
	}

	rollback := valid
	rollback.Revision = 1
	if err := controller.accept(rollback, fixedNow); err == nil {
		t.Fatal("rollback policy was accepted")
	}
}

func TestWrapperRestrictsManagedOperations(t *testing.T) {
	raw := &fakeLifecycleServer{}
	wrapper := Wrap(context.Background(), raw, "").(*wrappedServer)

	if _, err := wrapper.Down(context.Background(), &proto.DownRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Down error = %v, want PermissionDenied", err)
	}
	if _, err := wrapper.Logout(context.Background(), &proto.LogoutRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Logout error = %v, want PermissionDenied", err)
	}
	if _, err := wrapper.SetConfig(context.Background(), &proto.SetConfigRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetConfig error = %v, want PermissionDenied", err)
	}
	if _, err := wrapper.SwitchProfile(context.Background(), &proto.SwitchProfileRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SwitchProfile error = %v, want PermissionDenied", err)
	}
	if raw.downCalls != 0 {
		t.Fatalf("raw Down calls = %d, want 0", raw.downCalls)
	}

	features, err := wrapper.GetFeatures(context.Background(), &proto.GetFeaturesRequest{})
	if err != nil {
		t.Fatalf("GetFeatures: %v", err)
	}
	if !features.DisableProfiles || !features.DisableUpdateSettings || !features.DisableNetworks ||
		features.DisableAdvancedView == nil || !*features.DisableAdvancedView {
		t.Fatalf("managed feature flags were not all enforced: %+v", features)
	}
}

func TestKeepConnectedControlsDisconnectAndReconnects(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	raw := &fakeLifecycleServer{}
	controller := &policyController{
		raw: raw,
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			SchemaVersion:      4,
			Revision:           1,
			PolicyID:           "connection-policy",
			IssuedAt:           fixedNow.Add(-time.Minute),
			ValidUntil:         fixedNow.Add(time.Minute),
			NetBirdControls:    strictNetBirdControls(),
			EnterpriseControls: enterpriseControls{KeepConnected: false, DisableQuit: true},
			ExitNode:            exitNodePolicy{Mode: exitNodeDisabled},
		},
		hasSnapshot: true,
	}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	if _, err := wrapper.Down(context.Background(), &proto.DownRequest{}); err != nil {
		t.Fatalf("Down in USER_CONTROLLED mode: %v", err)
	}
	if raw.downCalls != 1 {
		t.Fatalf("raw Down calls = %d, want 1", raw.downCalls)
	}

	controller.snapshot.EnterpriseControls.KeepConnected = true
	if _, err := wrapper.Down(context.Background(), &proto.DownRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Down with keepConnected error = %v, want PermissionDenied", err)
	}
	controller.reconcile(context.Background())
	if raw.upCalls != 1 {
		t.Fatalf("raw Up calls = %d, want reconnect", raw.upCalls)
	}
	raw.status = string(internal.StatusConnected)
	controller.reconcile(context.Background())
	if raw.upCalls != 1 {
		t.Fatalf("raw Up calls = %d, want no reconnect while connected", raw.upCalls)
	}
}

func TestNativeControlsCanBeRelaxedOnlyByValidCurrentPolicy(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controls := strictNetBirdControls()
	controls[mdm.KeyDisableProfiles] = false
	controls[mdm.KeyDisableNetworks] = false
	controller := &policyController{
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			ValidUntil:      fixedNow.Add(time.Minute),
			NetBirdControls: controls,
			ExitNode:        exitNodePolicy{Mode: exitNodeUserControlled},
		},
		hasSnapshot: true,
	}
	raw := &fakeLifecycleServer{}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	features, err := wrapper.GetFeatures(context.Background(), &proto.GetFeaturesRequest{})
	if err != nil {
		t.Fatalf("GetFeatures: %v", err)
	}
	if features.GetDisableProfiles() || features.GetDisableNetworks() {
		t.Fatalf("valid false native controls were not honored: %+v", features)
	}
	if _, err := wrapper.SelectNetworks(context.Background(), &proto.SelectNetworksRequest{}); err != nil {
		t.Fatalf("SelectNetworks with USER_CONTROLLED exit node: %v", err)
	}
	if _, err := wrapper.SwitchProfile(context.Background(), &proto.SwitchProfileRequest{}); err != nil {
		t.Fatalf("SwitchProfile when disableProfiles=false: %v", err)
	}
	if raw.switchProfileCalls != 1 {
		t.Fatalf("raw SwitchProfile calls = %d, want 1", raw.switchProfileCalls)
	}

	controller.snapshot.ValidUntil = fixedNow
	features, err = wrapper.GetFeatures(context.Background(), &proto.GetFeaturesRequest{})
	if err != nil {
		t.Fatalf("GetFeatures after expiry: %v", err)
	}
	if !features.GetDisableProfiles() || !features.GetDisableNetworks() {
		t.Fatalf("expired native controls did not fail closed: %+v", features)
	}
}

func TestDisableAutoConnectIsAppliedAndReportedManaged(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controls := strictNetBirdControls()
	controls[mdm.KeyDisableAutoConnect] = true
	raw := &fakeLifecycleServer{config: &proto.GetConfigResponse{DisableAutoConnect: false}}
	controller := &policyController{
		raw: raw,
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			ValidUntil:        fixedNow.Add(time.Minute),
			NetBirdControls:   controls,
			EnterpriseControls: enterpriseControls{KeepConnected: false, DisableQuit: true},
			ExitNode:          exitNodePolicy{Mode: exitNodeUserControlled},
		},
		hasSnapshot: true,
	}
	controller.reconcile(context.Background())
	if len(raw.setConfigRequests) != 1 || raw.setConfigRequests[0].DisableAutoConnect == nil ||
		!raw.setConfigRequests[0].GetDisableAutoConnect() {
		t.Fatalf("SetConfig requests = %+v, want disableAutoConnect=true", raw.setConfigRequests)
	}

	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}
	config, err := wrapper.GetConfig(context.Background(), &proto.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !config.GetDisableAutoConnect() || !containsString(config.GetMDMManagedFields(), mdm.KeyDisableAutoConnect) ||
		!containsString(config.GetMDMManagedFields(), "disableQuit") {
		t.Fatalf("managed config was not projected: %+v", config)
	}
}

func TestKeepConnectedRejectsDisableAutoConnectConflict(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controls := strictNetBirdControls()
	controls[mdm.KeyDisableAutoConnect] = true
	candidate := policyResponse{
		SchemaVersion:      4,
		Revision:           1,
		PolicyID:           "conflict",
		IssuedAt:           fixedNow.Add(-time.Minute),
		ValidUntil:         fixedNow.Add(time.Minute),
		NetBirdControls:    controls,
		EnterpriseControls: enterpriseControls{KeepConnected: true, DisableQuit: true},
		ExitNode:           exitNodePolicy{Mode: exitNodeDisabled},
	}
	controller := &policyController{}
	if err := controller.accept(candidate, fixedNow); err == nil {
		t.Fatal("keepConnected + disableAutoConnect conflict was accepted")
	}
}

func TestEnterpriseControlsJSONRequiresBothBooleans(t *testing.T) {
	for _, body := range []string{
		`{"keepConnected":true}`,
		`{"disableQuit":true}`,
		`{"keepConnected":true,"disableQuit":true,"unknown":false}`,
	} {
		var controls enterpriseControls
		if err := json.Unmarshal([]byte(body), &controls); err == nil {
			t.Fatalf("invalid enterpriseControls JSON was accepted: %s", body)
		}
	}
}

func TestManagementURLIsLockedOnLoginAndSettingsUpdate(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controls := strictNetBirdControls()
	controls[mdm.KeyDisableUpdateSettings] = false
	raw := &fakeLifecycleServer{}
	controller := &policyController{
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			ValidUntil:         fixedNow.Add(time.Minute),
			NetBirdControls:    controls,
			EnterpriseControls: enterpriseControls{KeepConnected: false, DisableQuit: false},
			ExitNode:           exitNodePolicy{Mode: exitNodeUserControlled},
		},
		hasSnapshot: true,
	}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	if _, err := wrapper.Login(context.Background(), &proto.LoginRequest{
		ManagementUrl: "https://attacker.invalid",
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(raw.loginRequests) != 1 || raw.loginRequests[0].GetManagementUrl() != managementURL {
		t.Fatalf("Login management URL = %+v, want %s", raw.loginRequests, managementURL)
	}

	disableAutoConnect := true
	if _, err := wrapper.SetConfig(context.Background(), &proto.SetConfigRequest{
		ManagementUrl:      "https://attacker.invalid",
		DisableAutoConnect: &disableAutoConnect,
	}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if len(raw.setConfigRequests) != 1 || raw.setConfigRequests[0].GetManagementUrl() != managementURL ||
		raw.setConfigRequests[0].GetDisableAutoConnect() {
		t.Fatalf("locked SetConfig request = %+v", raw.setConfigRequests)
	}
}

func TestExitNodePolicyPinsAndDisablesOnlyDefaultRoutes(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	raw := &fakeLifecycleServer{networks: []*proto.Network{
		{ID: "exit-a", Range: "0.0.0.0/0, ::/0"},
		{ID: "exit-b", Range: "0.0.0.0/0", Selected: true},
		{ID: "corp", Range: "10.0.0.0/8", Selected: true},
	}}
	controller := &policyController{
		raw: raw,
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			ValidUntil: fixedNow.Add(time.Minute),
			ExitNode:   exitNodePolicy{Mode: exitNodePinned, NetworkID: "exit-a"},
		},
		hasSnapshot: true,
	}

	controller.reconcileExitNode(context.Background())
	if len(raw.selectRequests) != 1 || len(raw.selectRequests[0].GetNetworkIDs()) != 1 ||
		raw.selectRequests[0].GetNetworkIDs()[0] != "exit-a" || !raw.selectRequests[0].GetAppend() {
		t.Fatalf("pin request = %+v, want append selection of exit-a", raw.selectRequests)
	}

	controller.snapshot.ExitNode = exitNodePolicy{Mode: exitNodeDisabled}
	raw.networks[0].Selected = true
	raw.networks[1].Selected = false
	controller.reconcileExitNode(context.Background())
	if len(raw.deselectRequests) != 1 || len(raw.deselectRequests[0].GetNetworkIDs()) != 1 ||
		raw.deselectRequests[0].GetNetworkIDs()[0] != "exit-a" {
		t.Fatalf("disable request = %+v, want only exit-a", raw.deselectRequests)
	}
}

func TestManagedExitNodeStillAllowsOrdinaryRouteSelection(t *testing.T) {
	fixedNow := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	controls := strictNetBirdControls()
	controls[mdm.KeyDisableNetworks] = false
	raw := &fakeLifecycleServer{networks: []*proto.Network{
		{ID: "exit-a", Range: "0.0.0.0/0"},
		{ID: "corp", Range: "10.0.0.0/8"},
	}}
	controller := &policyController{
		now: func() time.Time { return fixedNow },
		snapshot: policyResponse{
			ValidUntil:        fixedNow.Add(time.Minute),
			NetBirdControls:   controls,
			EnterpriseControls: enterpriseControls{KeepConnected: true, DisableQuit: true},
			ExitNode:          exitNodePolicy{Mode: exitNodeDisabled},
		},
		hasSnapshot: true,
	}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	if _, err := wrapper.SelectNetworks(context.Background(), &proto.SelectNetworksRequest{
		NetworkIDs: []string{"corp"}, Append: true,
	}); err != nil {
		t.Fatalf("ordinary route selection: %v", err)
	}
	if _, err := wrapper.SelectNetworks(context.Background(), &proto.SelectNetworksRequest{
		NetworkIDs: []string{"exit-a"}, Append: true,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("exit-node selection error = %v, want PermissionDenied", err)
	}
	if len(raw.selectRequests) != 1 || raw.selectRequests[0].GetNetworkIDs()[0] != "corp" {
		t.Fatalf("delegated route requests = %+v, want only corp", raw.selectRequests)
	}
}

func TestForceDisconnectNotificationUsesJSONIdentity(t *testing.T) {
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestReceived = true
		if request.URL.Path != "/force-disconnect" || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if _, ok := payload["system_serial_number"]; !ok || payload["peer_public_key"] != "test-peer-key" {
			t.Errorf("force-disconnect identity missing: %+v", payload)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	controller := newPolicyController(&fakeLifecycleServer{}, "test-peer-key", nil)
	controller.forceEndpoint = server.URL + "/force-disconnect"
	controller.now = func() time.Time { return time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC) }
	controller.notifyForceDisconnect()
	if !requestReceived {
		t.Fatal("force-disconnect request was not received")
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func TestExitNodePolicyRejectsInvalidCombinations(t *testing.T) {
	if err := validateNetBirdControls(netBirdControls{"disableUnknown": true}); err == nil {
		t.Fatal("unknown native control was accepted")
	}
	if err := validateExitNode(exitNodePolicy{Mode: exitNodePinned}); err == nil {
		t.Fatal("PINNED without network_id was accepted")
	}
	if err := validateExitNode(exitNodePolicy{Mode: exitNodeDisabled, NetworkID: "exit-a"}); err == nil {
		t.Fatal("DISABLED with network_id was accepted")
	}
	if !isExitNodeRange("0.0.0.0/0, ::/0") || isExitNodeRange("10.0.0.0/8") {
		t.Fatal("exit-node range classification is incorrect")
	}
}

func TestEveryDaemonRPCIsClassified(t *testing.T) {
	const (
		readOnly = "READ_ONLY"
		connect = "CONNECT"
		disconnect = "DISCONNECT"
		authentication = "AUTHENTICATION"
		localDeregistration = "LOCAL_DEREGISTRATION"
		configMutation = "CONFIG_MUTATION"
		profileMutation = "PROFILE_MUTATION"
		update = "UPDATE"
		diagnostics = "DIAGNOSTICS"
	)
	classified := map[string]string{
		"Login":                      authentication,
		"WaitSSOLogin":               authentication,
		"Up":                         connect,
		"Status":                     readOnly,
		"SubscribeStatus":            readOnly,
		"Down":                       disconnect,
		"GetConfig":                  readOnly,
		"ListNetworks":               readOnly,
		"SelectNetworks":             configMutation,
		"DeselectNetworks":           configMutation,
		"ForwardingRules":            readOnly,
		"DebugBundle":                diagnostics,
		"GetLogLevel":                readOnly,
		"SetLogLevel":                configMutation,
		"ListStates":                 readOnly,
		"CleanState":                 configMutation,
		"DeleteState":                configMutation,
		"SetSyncResponsePersistence": configMutation,
		"TracePacket":                diagnostics,
		"StartCapture":               diagnostics,
		"StartBundleCapture":         diagnostics,
		"StopBundleCapture":          diagnostics,
		"SubscribeEvents":            readOnly,
		"GetEvents":                  readOnly,
		"RegisterUILog":              diagnostics,
		"SwitchProfile":              profileMutation,
		"SetConfig":                  configMutation,
		"AddProfile":                 profileMutation,
		"RenameProfile":              profileMutation,
		"RemoveProfile":              profileMutation,
		"ListProfiles":               readOnly,
		"GetActiveProfile":           readOnly,
		"Logout":                     localDeregistration,
		"GetFeatures":                readOnly,
		"TriggerUpdate":              update,
		"GetPeerSSHHostKey":          readOnly,
		"RequestJWTAuth":              authentication,
		"WaitJWTToken":               authentication,
		"RequestExtendAuthSession":    authentication,
		"WaitExtendAuthSession":       authentication,
		"DismissSessionWarning":       authentication,
		"StartCPUProfile":             diagnostics,
		"StopCPUProfile":              diagnostics,
		"GetInstallerResult":          readOnly,
		"ExposeService":               configMutation,
		"WailsUIReady":                readOnly,
	}

	seen := make(map[string]bool)
	for _, method := range proto.DaemonService_ServiceDesc.Methods {
		seen[method.MethodName] = true
		if _, ok := classified[method.MethodName]; !ok {
			t.Errorf("unclassified unary RPC: %s", method.MethodName)
		}
	}
	for _, stream := range proto.DaemonService_ServiceDesc.Streams {
		seen[stream.StreamName] = true
		if _, ok := classified[stream.StreamName]; !ok {
			t.Errorf("unclassified streaming RPC: %s", stream.StreamName)
		}
	}
	for method := range classified {
		if !seen[method] {
			t.Errorf("classification references missing RPC: %s", method)
		}
	}
}
