//go:build enterprise

package enterprise

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

const updateRequiredBody = `{"error":"CLIENT_UPDATE_REQUIRED","requiredVersion":"0.80.0+codebuckets.7","artifacts":[` +
	`{"platform":"windows-amd64","url":"https://netbird-client.download.codebuckets.in/releases/v0.80.0-enterprise.7/netbird-enterprise-windows-amd64.zip"},` +
	`{"platform":"windows-arm64","url":"https://netbird-client.download.codebuckets.in/releases/v0.80.0-enterprise.7/netbird-enterprise-windows-arm64.zip"}]}`

func TestRefusalNamesTheBuildToInstallAndWhereToGetIt(t *testing.T) {
	gate := newUpdateGate("0.80.0+codebuckets.6")
	if gate.denial() != nil || gate.requiredVersion() != "" {
		t.Fatal("a build that was never refused is told to update")
	}

	gate.require([]byte(updateRequiredBody))
	if got := gate.requiredVersion(); got != "0.80.0+codebuckets.7" {
		t.Fatalf("required version = %q, want the version the server named", got)
	}
	denial := gate.denial()
	if status.Code(denial) != codes.FailedPrecondition {
		t.Fatalf("denial = %v, want FailedPrecondition", denial)
	}
	wantURL := "https://netbird-client.download.codebuckets.in/releases/v0.80.0-enterprise.7/netbird-enterprise-" + platformName() + ".zip"
	for _, want := range []string{errUpdateRequired, "0.80.0+codebuckets.6", "0.80.0+codebuckets.7", wantURL} {
		if !strings.Contains(denial.Error(), want) {
			t.Errorf("denial %q does not mention %q", denial, want)
		}
	}

	gate.clear()
	if gate.denial() != nil {
		t.Fatal("a build the server serves again is still told to update")
	}
}

func TestRefusalWithoutAUsableBodyStillBlocksAndPointsAtTheDownloadHost(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":           nil,
		"not JSON":        []byte("<html>"),
		"code only":       []byte(`{"error":"CLIENT_UPDATE_REQUIRED"}`),
		"other platform":  []byte(`{"requiredVersion":"0.80.0+codebuckets.7","artifacts":[{"platform":"plan9-mips","url":"https://example.invalid/x.zip"}]}`),
		"missing version": []byte(`{"artifacts":[]}`),
	} {
		gate := newUpdateGate("0.80.0+codebuckets.6")
		gate.require(body)
		denial := gate.denial()
		if denial == nil {
			t.Fatalf("%s: no denial after a refusal", name)
		}
		if !strings.Contains(denial.Error(), releaseBaseURL) {
			t.Errorf("%s: denial %q does not point at the download host", name, denial)
		}
	}
}

func TestOutdatedBuildIsDisconnectedAndCannotConnect(t *testing.T) {
	gate := newUpdateGate("0.80.0+codebuckets.6")
	gate.require([]byte(updateRequiredBody))

	raw := &fakeLifecycleServer{status: string(internal.StatusConnected)}
	controller := controllerWithPolicy(raw, validPolicy(nil))
	controller.updates = gate
	wrapper := &wrappedServer{LifecycleServer: raw, policy: controller}

	controller.reconcile(context.Background())
	if raw.downCalls != 1 || raw.upCalls != 0 {
		t.Fatalf("Down calls = %d, Up calls = %d, want the outdated build disconnected and not reconnected", raw.downCalls, raw.upCalls)
	}

	// keepConnected must not bring an outdated build back.
	raw.status = string(internal.StatusIdle)
	controller.reconcile(context.Background())
	if raw.upCalls != 0 || raw.downCalls != 1 {
		t.Fatalf("Down calls = %d, Up calls = %d, want an idle outdated build left alone", raw.downCalls, raw.upCalls)
	}

	if _, err := wrapper.Up(context.Background(), &proto.UpRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Up error = %v, want FailedPrecondition", err)
	}
	if _, err := wrapper.Login(context.Background(), &proto.LoginRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Login error = %v, want FailedPrecondition", err)
	}
	if raw.upCalls != 0 || len(raw.loginRequests) != 0 {
		t.Fatalf("Up calls = %d, Login calls = %d, want neither to reach the daemon", raw.upCalls, len(raw.loginRequests))
	}
}

func TestPolicyServerRefusalMarksTheBuildOutdatedUntilItIsServedAgain(t *testing.T) {
	refuse := true
	controller, calls := newPollingController(t, func(writer http.ResponseWriter, request *http.Request) {
		if refuse {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusUpgradeRequired)
			_, _ = writer.Write([]byte(updateRequiredBody))
			return
		}
		servePolicy(policyBody(`{}`))(writer, request)
	})

	if err := controller.poll(context.Background()); err == nil {
		t.Fatal("a refused poll succeeded")
	}
	if got := controller.updates.requiredVersion(); got != "0.80.0+codebuckets.7" {
		t.Fatalf("required version = %q, want the build marked outdated", got)
	}

	// The build keeps asking, so it notices when the server accepts it again.
	controller.pollAndReconcile(context.Background())
	if got := calls.Load(); got != 2 {
		t.Fatalf("policy server calls = %d, want the outdated build to keep polling", got)
	}
	refuse = false
	if err := controller.poll(context.Background()); err != nil {
		t.Fatalf("poll once served again: %v", err)
	}
	if controller.updates.requiredVersion() != "" {
		t.Fatal("a build the server serves again is still marked outdated")
	}
}
