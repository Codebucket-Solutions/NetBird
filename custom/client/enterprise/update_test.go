//go:build enterprise

package enterprise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

func TestBuildVersionOrder(t *testing.T) {
	for _, test := range []struct {
		older, newer string
	}{
		{older: "0.80.0+codebuckets.6", newer: "0.80.0+codebuckets.7"},
		{older: "0.80.0+codebuckets.9", newer: "0.80.0+codebuckets.10"},
		{older: "0.80.9+codebuckets.9", newer: "0.81.0+codebuckets.1"},
		{older: "0.99.0+codebuckets.3", newer: "1.0.0+codebuckets.1"},
	} {
		older, okOlder := parseBuildVersion(test.older)
		newer, okNewer := parseBuildVersion(test.newer)
		if !okOlder || !okNewer {
			t.Fatalf("parse %q and %q: %t, %t", test.older, test.newer, okOlder, okNewer)
		}
		if !older.olderThan(newer) || newer.olderThan(older) || older.olderThan(older) {
			t.Errorf("%s must be older than %s, and no version older than itself", test.older, test.newer)
		}
	}

	for _, unusable := range []string{"", "development", "0.80.0", "0.80+codebuckets.1", "0.80.0+codebuckets.", "0.80.0+other.1", "0.x.0+codebuckets.1", "0.80.0+codebuckets.-1"} {
		if _, ok := parseBuildVersion(unusable); ok {
			t.Errorf("parseBuildVersion(%q) succeeded, want it refused", unusable)
		}
	}
}

// newTestGate returns a gate for the given build that reads its manifest from a
// test server, and a function that sets what that server answers.
func newTestGate(t *testing.T, current string) (*updateGate, func(status int, body string)) {
	t.Helper()
	answer := struct {
		status int
		body   string
	}{status: http.StatusOK, body: `{"version":"` + current + `"}`}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(answer.status)
		_, _ = writer.Write([]byte(answer.body))
	}))
	t.Cleanup(server.Close)

	gate := newUpdateGate(current, server.Client(), func() time.Time { return fixedNow })
	gate.manifestURL = server.URL
	return gate, func(status int, body string) {
		answer.status = status
		answer.body = body
	}
}

func TestNewerReleaseRequiresAnUpdate(t *testing.T) {
	gate, answer := newTestGate(t, "0.80.0+codebuckets.6")

	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if gate.requiredVersion() != "" || gate.denial() != nil {
		t.Fatalf("the latest build was told to update to %q", gate.requiredVersion())
	}

	answer(http.StatusOK, `{"version":"0.80.0+codebuckets.7","publishedAt":"2026-10-02T15:00:00Z"}`)
	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := gate.requiredVersion(); got != "0.80.0+codebuckets.7" {
		t.Fatalf("required version = %q, want the newer release", got)
	}
	denial := gate.denial()
	if status.Code(denial) != codes.FailedPrecondition {
		t.Fatalf("denial = %v, want FailedPrecondition", denial)
	}
	for _, want := range []string{errUpdateRequired, "0.80.0+codebuckets.6", "0.80.0+codebuckets.7", releaseBaseURL} {
		if !strings.Contains(denial.Error(), want) {
			t.Errorf("denial %q does not mention %q", denial, want)
		}
	}

	// A manifest that names this build again, or an older one, lifts the requirement.
	answer(http.StatusOK, `{"version":"0.80.0+codebuckets.5"}`)
	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if gate.requiredVersion() != "" {
		t.Fatalf("required version = %q after the manifest named an older build", gate.requiredVersion())
	}
}

func TestUnreadableManifestKeepsWhatWasKnown(t *testing.T) {
	gate, answer := newTestGate(t, "0.80.0+codebuckets.6")
	answer(http.StatusOK, `{"version":"0.81.0+codebuckets.1"}`)
	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for name, broken := range map[string]struct {
		status int
		body   string
	}{
		"server error":      {status: http.StatusInternalServerError, body: `{}`},
		"not JSON":          {status: http.StatusOK, body: `<html>`},
		"unusable version":  {status: http.StatusOK, body: `{"version":"latest"}`},
		"oversized":         {status: http.StatusOK, body: `{"version":"0.80.0+codebuckets.6"}` + strings.Repeat(" ", maxManifestBodyBytes)},
		"development build": {status: http.StatusOK, body: `{"version":"development"}`},
	} {
		answer(broken.status, broken.body)
		if err := gate.refresh(context.Background()); err == nil {
			t.Errorf("%s: refresh succeeded, want an error", name)
		}
		if got := gate.requiredVersion(); got != "0.81.0+codebuckets.1" {
			t.Errorf("%s: required version = %q, want the last definite answer kept", name, got)
		}
	}
}

func TestDevelopmentBuildIsOutsideTheReleaseOrder(t *testing.T) {
	gate, answer := newTestGate(t, "development")
	answer(http.StatusOK, `{"version":"9.9.9+codebuckets.9"}`)

	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if gate.requiredVersion() != "" {
		t.Fatalf("a development build was told to update to %q", gate.requiredVersion())
	}
}

func TestManifestIsReadOncePerInterval(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = writer.Write([]byte(`{"version":"0.80.0+codebuckets.6"}`))
	}))
	t.Cleanup(server.Close)
	now := fixedNow
	gate := newUpdateGate("0.80.0+codebuckets.6", server.Client(), func() time.Time { return now })
	gate.manifestURL = server.URL

	gate.refreshIfDue(context.Background())
	gate.refreshIfDue(context.Background())
	now = now.Add(releaseCheckInterval - time.Second)
	gate.refreshIfDue(context.Background())
	if requests != 1 {
		t.Fatalf("manifest requests = %d, want 1 inside the interval", requests)
	}
	now = now.Add(time.Second)
	gate.refreshIfDue(context.Background())
	if requests != 2 {
		t.Fatalf("manifest requests = %d, want 2 once the interval has passed", requests)
	}
}

func TestOutdatedBuildIsDisconnectedAndCannotConnect(t *testing.T) {
	gate, answer := newTestGate(t, "0.80.0+codebuckets.6")
	answer(http.StatusOK, `{"version":"0.80.0+codebuckets.7"}`)
	if err := gate.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

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

func TestPolicyServerRefusalMarksTheBuildOutdated(t *testing.T) {
	controller, calls := newPollingController(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUpgradeRequired)
		_, _ = writer.Write([]byte(`{"error":"CLIENT_UPDATE_REQUIRED"}`))
	})

	if err := controller.poll(context.Background()); err == nil {
		t.Fatal("a refused poll succeeded")
	}
	if got := controller.updates.requiredVersion(); got != latestRelease {
		t.Fatalf("required version = %q, want the build marked outdated", got)
	}

	// Once outdated, the loop stops asking the policy server.
	controller.pollAndReconcile(context.Background())
	if got := calls.Load(); got != 1 {
		t.Fatalf("policy server calls = %d, want no further poll from an outdated build", got)
	}
}
