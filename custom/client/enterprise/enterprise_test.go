//go:build enterprise

package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

var fixedNow = time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)

type fakeLifecycleServer struct {
	proto.UnimplementedDaemonServiceServer
	upCalls            int
	downCalls          int
	logoutCalls        int
	switchProfileCalls int
	status             string
	localIP            string
	features           *proto.GetFeaturesResponse
	config             *proto.GetConfigResponse
	networks           []*proto.Network
	loginRequests      []*proto.LoginRequest
	selectRequests     []*proto.SelectNetworksRequest
	deselectRequests   []*proto.SelectNetworksRequest
	setConfigRequests  []*proto.SetConfigRequest
	getConfigRequests  []*proto.GetConfigRequest
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

// Status mirrors the daemon: the local peer state is returned only when the
// full peer status is requested, and its IP is empty until the peer registers.
func (f *fakeLifecycleServer) Status(_ context.Context, request *proto.StatusRequest) (*proto.StatusResponse, error) {
	response := &proto.StatusResponse{Status: f.status}
	if request.GetGetFullPeerStatus() {
		response.FullStatus = &proto.FullStatus{LocalPeerState: &proto.LocalPeerState{IP: f.localIP}}
	}
	return response, nil
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

// GetActiveProfile mirrors a daemon running its default profile.
func (*fakeLifecycleServer) GetActiveProfile(context.Context, *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	return &proto.GetActiveProfileResponse{ProfileName: "default", Id: "default", Username: "alice"}, nil
}

// GetConfig mirrors the daemon, which rejects a request that names no profile.
func (f *fakeLifecycleServer) GetConfig(_ context.Context, request *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	if request.GetProfileName() == "" {
		return nil, status.Error(codes.Unknown, "profile handle is empty")
	}
	f.getConfigRequests = append(f.getConfigRequests, request)
	if f.config == nil {
		return &proto.GetConfigResponse{}, nil
	}
	return f.config, nil
}

func (f *fakeLifecycleServer) SetConfig(_ context.Context, request *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	if request.GetProfileName() == "" {
		return nil, status.Error(codes.Unknown, "profile handle is empty")
	}
	f.setConfigRequests = append(f.setConfigRequests, request)
	if request.GetDisableAutoConnect() && f.config != nil {
		f.config.DisableAutoConnect = true
	}
	return &proto.SetConfigResponse{}, nil
}

func controlValues(values map[string]bool) map[string]*bool {
	controls := make(map[string]*bool, len(values))
	for key, value := range values {
		enabled := value
		controls[key] = &enabled
	}
	return controls
}

// validPolicy returns an acceptable policy carrying every known control at its
// strict value, with the given overrides applied.
func validPolicy(overrides map[string]bool) policyResponse {
	values := map[string]bool{
		controlKeepConnected:         true,
		controlDisableQuit:           true,
		mdm.KeyDisableUpdateSettings: true,
		mdm.KeyDisableProfiles:       true,
		mdm.KeyDisableNetworks:       true,
		mdm.KeyDisableAdvancedView:   true,
		mdm.KeyDisableAutoConnect:    false,
	}
	for key, value := range overrides {
		values[key] = value
	}
	return policyResponse{
		PolicyID:   "test-policy",
		ValidUntil: fixedNow.Add(time.Minute),
		Controls:   controlValues(values),
		ExitNode:   exitNodePolicy{Mode: exitNodeDisabled},
	}
}

func controllerWithPolicy(raw LifecycleServer, policy policyResponse) *policyController {
	return &policyController{
		raw:         raw,
		now:         func() time.Time { return fixedNow },
		snapshot:    policy,
		hasSnapshot: true,
	}
}

// policyBody renders a wire response whose controls object is given verbatim.
func policyBody(controls string) string {
	return fmt.Sprintf(
		`{"policyId":"test-policy","validUntil":%q,"controls":%s,"exitNode":{"mode":"DISABLED","networkId":""}}`,
		fixedNow.Add(time.Minute).Format(time.RFC3339), controls,
	)
}

// servePolicy answers at fixedNow on the server's clock, so a lease is measured
// against the same instant the test controller uses.
func servePolicy(body string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Date", fixedNow.Format(http.TimeFormat))
		_, _ = writer.Write([]byte(body))
	}
}

// newPollingController returns a controller for a registered peer that polls a
// test server, plus the number of requests that server has received.
func newPollingController(t *testing.T, handler http.HandlerFunc) (*policyController, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		handler(writer, request)
	}))
	t.Cleanup(server.Close)

	t.Setenv(policyTokenEnv, "fleet-token")
	controller := newPolicyController(&fakeLifecycleServer{localIP: "100.64.12.7/24"}, nil)
	controller.endpoint = server.URL
	controller.now = func() time.Time { return fixedNow }
	return controller, calls
}

func TestPolicyPollSendsOnlyNetBirdIPAndSerial(t *testing.T) {
	controller, calls := newPollingController(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		for header, want := range map[string]string{
			"Accept":        "application/json",
			"Content-Type":  "application/json",
			"Authorization": "Bearer fleet-token",
		} {
			if got := request.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}

		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(payload) != 2 {
			t.Errorf("request fields = %v, want exactly netbirdIp and serialNumber", payload)
		}
		if payload["netbirdIp"] != "100.64.12.7" {
			t.Errorf("netbirdIp = %v, want 100.64.12.7", payload["netbirdIp"])
		}
		if _, ok := payload["serialNumber"].(string); !ok {
			t.Errorf("serialNumber = %v, want a string", payload["serialNumber"])
		}

		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Date", fixedNow.Format(http.TimeFormat))
		if err := json.NewEncoder(writer).Encode(validPolicy(nil)); err != nil {
			t.Errorf("encode response: %v", err)
		}
	})

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("policy server calls = %d, want 1", got)
	}
	if got := controller.enterpriseControls(fixedNow); !got.KeepConnected || !got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want strict controls", got)
	}

	const wantURL = "https://api.engineering-fabric.codebuckets.in/api/v1/netbird/client/policy"
	if got := newPolicyController(&fakeLifecycleServer{}, nil).endpoint; got != wantURL {
		t.Fatalf("policy endpoint = %s, want %s", got, wantURL)
	}
	if policyPollInterval != 15*time.Second {
		t.Fatalf("poll interval = %s, want 15s", policyPollInterval)
	}
}

func TestPolicyPollSendsNoRequestWithoutNetBirdIP(t *testing.T) {
	controller, calls := newPollingController(t, servePolicy(policyBody(`{"keepConnected":false}`)))
	controller.raw = &fakeLifecycleServer{}

	if err := controller.poll(context.Background()); err == nil {
		t.Fatal("poll without a NetBird IP did not fail")
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("policy server calls = %d, want 0", got)
	}
	if got := controller.enterpriseControls(fixedNow); got != strictEnterpriseControls() {
		t.Fatalf("enterprise controls = %+v, want strict controls", got)
	}
}

func TestPolicyPollKeepsUsingTheLastNetBirdIPWhileDisconnected(t *testing.T) {
	controller, calls := newPollingController(t, servePolicy(policyBody(`{"keepConnected":false}`)))
	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll while connected: %v", err)
	}

	// A disconnected daemon reports no local address.
	controller.raw = &fakeLifecycleServer{}
	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll while disconnected: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("policy server calls = %d, want the disconnected poll to reach the server too", got)
	}
	if got := controller.enterpriseControls(fixedNow); got.KeepConnected {
		t.Fatalf("enterprise controls = %+v, want keepConnected=false to stay in force", got)
	}
}

func TestLeaseIsMeasuredOnTheServerClock(t *testing.T) {
	serverNow := fixedNow.Add(40 * time.Minute)
	body := func(lease time.Duration) string {
		return fmt.Sprintf(
			`{"policyId":"test-policy","validUntil":%q,"controls":{},"exitNode":{"mode":"DISABLED","networkId":""}}`,
			serverNow.Add(lease).Format(time.RFC3339),
		)
	}
	serve := func(lease time.Duration) http.HandlerFunc {
		return func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Date", serverNow.Format(http.TimeFormat))
			_, _ = writer.Write([]byte(body(lease)))
		}
	}

	// The local clock is forty minutes behind the server. Judged on the local
	// clock this lease would look forty-five minutes long and be refused.
	controller, _ := newPollingController(t, serve(5*time.Minute))
	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll with a skewed local clock: %v", err)
	}
	if got := controller.snapshot.ValidUntil; !got.Equal(fixedNow.Add(5 * time.Minute)) {
		t.Fatalf("lease ends at %s, want five minutes after the local time of the poll", got)
	}

	tooLong, _ := newPollingController(t, serve(maxLeaseAhead+time.Minute))
	if err := tooLong.poll(context.Background()); err == nil {
		t.Fatal("a lease longer than the limit on the server clock was accepted")
	}
}

func TestFleetTokenSetAtLinkTimeWinsOverTheEnvironment(t *testing.T) {
	t.Setenv(policyTokenEnv, " development-token ")
	if got := fleetToken(); got != "development-token" {
		t.Fatalf("fleet token = %q, want the trimmed environment value", got)
	}

	policyToken = "linked-token"
	t.Cleanup(func() { policyToken = "" })
	if got := fleetToken(); got != "linked-token" {
		t.Fatalf("fleet token = %q, want the link-time value", got)
	}
}

func TestUnknownControlOfAnyTypeIsIgnored(t *testing.T) {
	controller, _ := newPollingController(t, servePolicy(policyBody(
		`{"keepConnected":false,"futureLimit":{"mbps":50},"futureLabel":"gold","futureList":[1,2]}`,
	)))

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll with unknown non-boolean controls: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); got.KeepConnected || !got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want keepConnected=false and strict disableQuit", got)
	}
}

func TestUnknownControlKeyIsIgnored(t *testing.T) {
	controller, _ := newPollingController(t, servePolicy(policyBody(
		`{"keepConnected":false,"disableFutureFeature":true}`,
	)))

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll with an unknown control key: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); got.KeepConnected || !got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want keepConnected=false and strict disableQuit", got)
	}
	if got := controller.netBirdControls(fixedNow); !reflect.DeepEqual(got, strictNetBirdControls()) {
		t.Fatalf("NetBird controls = %+v, want only the known strict controls", got)
	}
}

func TestUnknownTopLevelFieldIsIgnored(t *testing.T) {
	body := fmt.Sprintf(`{
		"policyId": "engineering-always-on:v7",
		"validUntil": %q,
		"futureField": {"nested": [1, 2, 3]},
		"controls": {"disableQuit": false},
		"exitNode": {"mode": "USER_CONTROLLED", "networkId": ""}
	}`, fixedNow.Add(5*time.Minute).Format(time.RFC3339))
	controller, _ := newPollingController(t, servePolicy(body))

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll with an unknown top-level field: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); !got.KeepConnected || got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want disableQuit=false and strict keepConnected", got)
	}
	if got := controller.exitNode(fixedNow); got.Mode != exitNodeUserControlled {
		t.Fatalf("exit node = %+v, want USER_CONTROLLED", got)
	}
}

func TestMissingOrNullControlFallsBackToStrictDefault(t *testing.T) {
	controller, _ := newPollingController(t, servePolicy(policyBody(
		`{"disableQuit":null,"disableProfiles":false}`,
	)))

	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll with a sparse control set: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); got != strictEnterpriseControls() {
		t.Fatalf("enterprise controls = %+v, want strict defaults", got)
	}
	want := strictNetBirdControls()
	want[mdm.KeyDisableProfiles] = false
	if got := controller.netBirdControls(fixedNow); !reflect.DeepEqual(got, want) {
		t.Fatalf("NetBird controls = %+v, want %+v", got, want)
	}
}

func TestPolicyPollRejectsInvalidResponses(t *testing.T) {
	const jsonType = "application/json"
	for _, test := range []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "error status", status: http.StatusForbidden, contentType: jsonType, body: `{"error":"PEER_UNKNOWN"}`},
		{name: "non-JSON content type", status: http.StatusOK, contentType: "text/plain", body: policyBody(`{}`)},
		{name: "trailing JSON value", status: http.StatusOK, contentType: jsonType, body: policyBody(`{}`) + `{}`},
		{name: "oversized body", status: http.StatusOK, contentType: jsonType, body: policyBody(`{}`) + strings.Repeat(" ", maxPolicyBodyBytes)},
		{name: "null controls", status: http.StatusOK, contentType: jsonType, body: policyBody(`null`)},
		{name: "non-boolean control", status: http.StatusOK, contentType: jsonType, body: policyBody(`{"keepConnected":"yes"}`)},
		{name: "missing controls", status: http.StatusOK, contentType: jsonType, body: strings.Replace(policyBody(`{}`), `"controls":{},`, "", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, calls := newPollingController(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.Header().Set("Date", fixedNow.Format(http.TimeFormat))
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			})

			if err := controller.poll(context.Background()); err == nil {
				t.Fatal("invalid policy response was accepted")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("policy server calls = %d, want 1", got)
			}
			if controller.hasSnapshot {
				t.Fatal("rejected response replaced the snapshot")
			}
		})
	}
}

func TestPolicyAcceptValidatesIdentityLeaseAndControls(t *testing.T) {
	if maxLeaseAhead != 15*time.Minute {
		t.Fatalf("lease limit = %s, want 15m", maxLeaseAhead)
	}
	for _, test := range []struct {
		name    string
		mutate  func(*policyResponse)
		wantErr bool
	}{
		{name: "valid policy", mutate: func(*policyResponse) {}},
		{name: "policyId of 256 bytes", mutate: func(p *policyResponse) { p.PolicyID = strings.Repeat("p", 256) }},
		{name: "empty policyId", mutate: func(p *policyResponse) { p.PolicyID = "" }, wantErr: true},
		{name: "policyId of 257 bytes", mutate: func(p *policyResponse) { p.PolicyID = strings.Repeat("p", 257) }, wantErr: true},
		{name: "missing validUntil", mutate: func(p *policyResponse) { p.ValidUntil = time.Time{} }, wantErr: true},
		{name: "validUntil in the past", mutate: func(p *policyResponse) { p.ValidUntil = fixedNow.Add(-time.Second) }, wantErr: true},
		{name: "validUntil equal to now", mutate: func(p *policyResponse) { p.ValidUntil = fixedNow }, wantErr: true},
		{name: "validUntil at the lease limit", mutate: func(p *policyResponse) { p.ValidUntil = fixedNow.Add(maxLeaseAhead) }},
		{name: "validUntil beyond the lease limit", mutate: func(p *policyResponse) { p.ValidUntil = fixedNow.Add(maxLeaseAhead + time.Second) }, wantErr: true},
		{name: "empty controls", mutate: func(p *policyResponse) { p.Controls = map[string]*bool{} }},
		{name: "missing controls", mutate: func(p *policyResponse) { p.Controls = nil }, wantErr: true},
		{name: "missing exitNode", mutate: func(p *policyResponse) { p.ExitNode = exitNodePolicy{} }, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPolicy(nil)
			test.mutate(&candidate)
			controller := &policyController{}

			err := controller.accept(candidate, fixedNow)
			if (err != nil) != test.wantErr {
				t.Fatalf("accept error = %v, want error %t", err, test.wantErr)
			}
			if controller.hasSnapshot == test.wantErr {
				t.Fatalf("snapshot installed = %t, want %t", controller.hasSnapshot, !test.wantErr)
			}
		})
	}
}

func TestKeepConnectedRejectsDisableAutoConnectConflict(t *testing.T) {
	for _, test := range []struct {
		name     string
		controls map[string]bool
		wantErr  bool
	}{
		{name: "both true", controls: map[string]bool{controlKeepConnected: true, mdm.KeyDisableAutoConnect: true}, wantErr: true},
		{name: "keepConnected omitted is strict", controls: map[string]bool{mdm.KeyDisableAutoConnect: true}, wantErr: true},
		{name: "keepConnected false", controls: map[string]bool{controlKeepConnected: false, mdm.KeyDisableAutoConnect: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPolicy(nil)
			candidate.Controls = controlValues(test.controls)

			err := (&policyController{}).accept(candidate, fixedNow)
			if (err != nil) != test.wantErr {
				t.Fatalf("accept error = %v, want error %t", err, test.wantErr)
			}
		})
	}
}

func TestExitNodePolicyValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		policy  exitNodePolicy
		wantErr bool
	}{
		{name: "DISABLED", policy: exitNodePolicy{Mode: exitNodeDisabled}},
		{name: "USER_CONTROLLED", policy: exitNodePolicy{Mode: exitNodeUserControlled}},
		{name: "PINNED", policy: exitNodePolicy{Mode: exitNodePinned, NetworkID: "exit-a"}},
		{name: "PINNED with 256 bytes", policy: exitNodePolicy{Mode: exitNodePinned, NetworkID: strings.Repeat("n", 256)}},
		{name: "missing mode", policy: exitNodePolicy{}, wantErr: true},
		{name: "unknown mode", policy: exitNodePolicy{Mode: "AUTOMATIC"}, wantErr: true},
		{name: "lower-case mode", policy: exitNodePolicy{Mode: "pinned", NetworkID: "exit-a"}, wantErr: true},
		{name: "PINNED without networkId", policy: exitNodePolicy{Mode: exitNodePinned}, wantErr: true},
		{name: "PINNED with padded networkId", policy: exitNodePolicy{Mode: exitNodePinned, NetworkID: " exit-a"}, wantErr: true},
		{name: "PINNED with 257 bytes", policy: exitNodePolicy{Mode: exitNodePinned, NetworkID: strings.Repeat("n", 257)}, wantErr: true},
		{name: "DISABLED with networkId", policy: exitNodePolicy{Mode: exitNodeDisabled, NetworkID: "exit-a"}, wantErr: true},
		{name: "USER_CONTROLLED with networkId", policy: exitNodePolicy{Mode: exitNodeUserControlled, NetworkID: "exit-a"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := validPolicy(nil)
			candidate.ExitNode = test.policy

			err := (&policyController{}).accept(candidate, fixedNow)
			if (err != nil) != test.wantErr {
				t.Fatalf("accept error = %v, want error %t", err, test.wantErr)
			}
		})
	}

	if !isExitNodeRange("0.0.0.0/0, ::/0") || isExitNodeRange("10.0.0.0/8") {
		t.Fatal("exit-node range classification is incorrect")
	}
}

func TestExpiredSnapshotReturnsStrictDefaults(t *testing.T) {
	relaxed := validPolicy(map[string]bool{
		controlKeepConnected:         false,
		controlDisableQuit:           false,
		mdm.KeyDisableUpdateSettings: false,
		mdm.KeyDisableProfiles:       false,
		mdm.KeyDisableNetworks:       false,
		mdm.KeyDisableAdvancedView:   false,
		mdm.KeyDisableAutoConnect:    true,
	})
	relaxed.ExitNode = exitNodePolicy{Mode: exitNodeUserControlled}
	controller := &policyController{}
	if err := controller.accept(relaxed, fixedNow); err != nil {
		t.Fatalf("accept relaxed policy: %v", err)
	}

	if got := controller.enterpriseControls(fixedNow); got.KeepConnected || got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want the accepted relaxation", got)
	}
	relaxedNetBirdControls := netBirdControls{
		mdm.KeyDisableUpdateSettings: false,
		mdm.KeyDisableProfiles:       false,
		mdm.KeyDisableNetworks:       false,
		mdm.KeyDisableAdvancedView:   false,
		mdm.KeyDisableAutoConnect:    true,
	}
	if got := controller.netBirdControls(fixedNow); !reflect.DeepEqual(got, relaxedNetBirdControls) {
		t.Fatalf("NetBird controls = %+v, want the accepted relaxation", got)
	}
	if got := controller.exitNode(fixedNow); got.Mode != exitNodeUserControlled {
		t.Fatalf("exit node = %+v, want USER_CONTROLLED", got)
	}

	expiry := relaxed.ValidUntil
	if got := controller.enterpriseControls(expiry); got != strictEnterpriseControls() {
		t.Fatalf("expired enterprise controls = %+v, want strict defaults", got)
	}
	if got := controller.netBirdControls(expiry); !reflect.DeepEqual(got, strictNetBirdControls()) {
		t.Fatalf("expired NetBird controls = %+v, want strict defaults", got)
	}
	if got := controller.exitNode(expiry); got != (exitNodePolicy{Mode: exitNodeDisabled}) {
		t.Fatalf("expired exit node = %+v, want DISABLED", got)
	}
}

func TestRejectedPolicyKeepsPreviousSnapshot(t *testing.T) {
	controller := &policyController{}
	relaxed := validPolicy(map[string]bool{controlKeepConnected: false, controlDisableQuit: false})
	if err := controller.accept(relaxed, fixedNow); err != nil {
		t.Fatalf("accept relaxed policy: %v", err)
	}

	invalid := validPolicy(nil)
	invalid.PolicyID = ""
	if err := controller.accept(invalid, fixedNow); err == nil {
		t.Fatal("policy without policyId was accepted")
	}
	if got := controller.enterpriseControls(fixedNow); got.KeepConnected || got.DisableQuit {
		t.Fatalf("enterprise controls = %+v, want the previous snapshot", got)
	}
}

func TestAcceptedPolicyReplacesSnapshot(t *testing.T) {
	controller := &policyController{}
	relaxed := validPolicy(map[string]bool{controlKeepConnected: false, controlDisableQuit: false})
	relaxed.PolicyID = "support-window:v2"
	relaxed.ValidUntil = fixedNow.Add(10 * time.Minute)
	if err := controller.accept(relaxed, fixedNow); err != nil {
		t.Fatalf("accept relaxed policy: %v", err)
	}

	// The newest accepted response wins even when its lease ends earlier:
	// there is no revision ordering between responses.
	strict := validPolicy(nil)
	strict.PolicyID = "engineering-always-on:v1"
	if err := controller.accept(strict, fixedNow); err != nil {
		t.Fatalf("accept strict policy: %v", err)
	}
	if got := controller.enterpriseControls(fixedNow); got != strictEnterpriseControls() {
		t.Fatalf("enterprise controls = %+v, want the replacing policy", got)
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
	raw := &fakeLifecycleServer{}
	controller := controllerWithPolicy(raw, validPolicy(map[string]bool{controlKeepConnected: false}))
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	if _, err := wrapper.Down(context.Background(), &proto.DownRequest{}); err != nil {
		t.Fatalf("Down with keepConnected=false: %v", err)
	}
	if raw.downCalls != 1 {
		t.Fatalf("raw Down calls = %d, want 1", raw.downCalls)
	}

	controller.snapshot = validPolicy(map[string]bool{controlKeepConnected: true})
	if _, err := wrapper.Down(context.Background(), &proto.DownRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Down with keepConnected error = %v, want PermissionDenied", err)
	}
	raw.status = string(internal.StatusIdle)
	controller.reconcile(context.Background())
	if raw.upCalls != 1 {
		t.Fatalf("raw Up calls = %d, want reconnect from idle", raw.upCalls)
	}

	// Up while a login is needed would cancel the sign-in the user has open, and
	// a daemon that is connecting or connected needs nothing.
	for _, daemonStatus := range []internal.StatusType{
		internal.StatusNeedsLogin,
		internal.StatusLoginFailed,
		internal.StatusSessionExpired,
		internal.StatusConnecting,
		internal.StatusConnected,
	} {
		raw.status = string(daemonStatus)
		controller.reconcile(context.Background())
		if raw.upCalls != 1 {
			t.Fatalf("raw Up calls = %d after status %s, want no further Up", raw.upCalls, daemonStatus)
		}
	}
}

func TestNativeControlsCanBeRelaxedOnlyByValidCurrentPolicy(t *testing.T) {
	policy := validPolicy(map[string]bool{
		mdm.KeyDisableProfiles: false,
		mdm.KeyDisableNetworks: false,
	})
	policy.ExitNode = exitNodePolicy{Mode: exitNodeUserControlled}
	controller := controllerWithPolicy(nil, policy)
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
	policy := validPolicy(map[string]bool{
		controlKeepConnected:      false,
		mdm.KeyDisableAutoConnect: true,
	})
	policy.ExitNode = exitNodePolicy{Mode: exitNodeUserControlled}
	raw := &fakeLifecycleServer{config: &proto.GetConfigResponse{DisableAutoConnect: false}}
	controller := controllerWithPolicy(raw, policy)

	controller.reconcile(context.Background())
	if len(raw.setConfigRequests) != 1 || raw.setConfigRequests[0].DisableAutoConnect == nil ||
		!raw.setConfigRequests[0].GetDisableAutoConnect() {
		t.Fatalf("SetConfig requests = %+v, want disableAutoConnect=true", raw.setConfigRequests)
	}
	if got := raw.setConfigRequests[0]; got.GetProfileName() != "default" || got.GetUsername() != "alice" {
		t.Fatalf("SetConfig addressed %q for %q, want the active profile", got.GetProfileName(), got.GetUsername())
	}

	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}
	config, err := wrapper.GetConfig(context.Background(), &proto.GetConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !config.GetDisableAutoConnect() || !containsString(config.GetMDMManagedFields(), mdm.KeyDisableAutoConnect) ||
		!containsString(config.GetMDMManagedFields(), controlDisableQuit) {
		t.Fatalf("managed config was not projected: %+v", config)
	}
}

func TestManagementURLIsLockedOnLoginAndSettingsUpdate(t *testing.T) {
	policy := validPolicy(map[string]bool{
		controlKeepConnected:         false,
		controlDisableQuit:           false,
		mdm.KeyDisableUpdateSettings: false,
	})
	policy.ExitNode = exitNodePolicy{Mode: exitNodeUserControlled}
	raw := &fakeLifecycleServer{}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controllerWithPolicy(nil, policy)}

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

func TestConfigCallsAreAddressedToTheActiveProfile(t *testing.T) {
	policy := validPolicy(map[string]bool{mdm.KeyDisableUpdateSettings: false})
	raw := &fakeLifecycleServer{}
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controllerWithPolicy(nil, policy)}

	// The tray asks for the config without naming a profile.
	if _, err := wrapper.GetConfig(context.Background(), &proto.GetConfigRequest{}); err != nil {
		t.Fatalf("GetConfig without a profile: %v", err)
	}
	if _, err := wrapper.GetConfig(context.Background(), &proto.GetConfigRequest{ProfileName: "work", Username: "bob"}); err != nil {
		t.Fatalf("GetConfig for a named profile: %v", err)
	}
	if len(raw.getConfigRequests) != 2 || raw.getConfigRequests[0].GetProfileName() != "default" ||
		raw.getConfigRequests[0].GetUsername() != "alice" || raw.getConfigRequests[1].GetProfileName() != "work" {
		t.Fatalf("GetConfig requests = %+v, want the active profile filled in and a named profile kept", raw.getConfigRequests)
	}

	// A settings change always lands on the active profile, whatever the caller names.
	if _, err := wrapper.SetConfig(context.Background(), &proto.SetConfigRequest{ProfileName: "work", Username: "bob"}); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if len(raw.setConfigRequests) != 1 || raw.setConfigRequests[0].GetProfileName() != "default" ||
		raw.setConfigRequests[0].GetUsername() != "alice" {
		t.Fatalf("SetConfig requests = %+v, want the active profile", raw.setConfigRequests)
	}
}

func TestExitNodePolicyPinsAndDisablesOnlyDefaultRoutes(t *testing.T) {
	raw := &fakeLifecycleServer{networks: []*proto.Network{
		{ID: "exit-a", Range: "0.0.0.0/0, ::/0"},
		{ID: "exit-b", Range: "0.0.0.0/0", Selected: true},
		{ID: "corp", Range: "10.0.0.0/8", Selected: true},
	}}
	policy := validPolicy(nil)
	policy.ExitNode = exitNodePolicy{Mode: exitNodePinned, NetworkID: "exit-a"}
	controller := controllerWithPolicy(raw, policy)

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
	raw := &fakeLifecycleServer{networks: []*proto.Network{
		{ID: "exit-a", Range: "0.0.0.0/0"},
		{ID: "corp", Range: "10.0.0.0/8"},
	}}
	controller := controllerWithPolicy(nil, validPolicy(map[string]bool{mdm.KeyDisableNetworks: false}))
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
	// The daemon hides the IPv6 half of an exit node from ListNetworks but
	// still accepts its ID.
	if _, err := wrapper.SelectNetworks(context.Background(), &proto.SelectNetworksRequest{
		NetworkIDs: []string{"exit-a-v6"}, Append: true,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("IPv6 exit-node selection error = %v, want PermissionDenied", err)
	}
	if len(raw.selectRequests) != 1 || raw.selectRequests[0].GetNetworkIDs()[0] != "corp" {
		t.Fatalf("delegated route requests = %+v, want only corp", raw.selectRequests)
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

func TestEveryDaemonRPCIsClassified(t *testing.T) {
	const (
		readOnly            = "READ_ONLY"
		connect             = "CONNECT"
		disconnect          = "DISCONNECT"
		authentication      = "AUTHENTICATION"
		localDeregistration = "LOCAL_DEREGISTRATION"
		configMutation      = "CONFIG_MUTATION"
		profileMutation     = "PROFILE_MUTATION"
		update              = "UPDATE"
		diagnostics         = "DIAGNOSTICS"
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
		"RequestJWTAuth":             authentication,
		"WaitJWTToken":               authentication,
		"RequestExtendAuthSession":   authentication,
		"WaitExtendAuthSession":      authentication,
		"DismissSessionWarning":      authentication,
		"StartCPUProfile":            diagnostics,
		"StopCPUProfile":             diagnostics,
		"GetInstallerResult":         readOnly,
		"ExposeService":              configMutation,
		"WailsUIReady":               readOnly,
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
