//go:build enterprise

package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// releaseBaseURL is where enterprise builds are published. latest.json at
	// its root names the only build that is allowed to connect.
	releaseBaseURL       = "https://netbird-client.download.codebuckets.in"
	releaseManifestURL   = releaseBaseURL + "/latest.json"
	releaseCheckInterval = 5 * time.Minute
	maxManifestBodyBytes = 64 * 1024

	errUpdateRequired = "ENTERPRISE_UPDATE_REQUIRED"

	// latestRelease stands in for the version when only the policy server has
	// said that this build is outdated.
	latestRelease = "the latest version"
)

// buildVersion identifies an enterprise build: the upstream release it is based
// on and the enterprise revision on top of it, as in 0.80.0+codebuckets.6.
type buildVersion struct {
	major, minor, patch, revision int
}

func parseBuildVersion(value string) (buildVersion, bool) {
	upstream, stamp, stamped := strings.Cut(strings.TrimPrefix(strings.TrimSpace(value), "v"), "+")
	revision, isEnterprise := strings.CutPrefix(stamp, "codebuckets.")
	parts := strings.Split(upstream, ".")
	if !stamped || !isEnterprise || len(parts) != 3 {
		return buildVersion{}, false
	}
	numbers := make([]int, 0, 4)
	for _, part := range append(parts, revision) {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return buildVersion{}, false
		}
		numbers = append(numbers, number)
	}
	return buildVersion{major: numbers[0], minor: numbers[1], patch: numbers[2], revision: numbers[3]}, true
}

func (v buildVersion) olderThan(other buildVersion) bool {
	mine := [4]int{v.major, v.minor, v.patch, v.revision}
	theirs := [4]int{other.major, other.minor, other.patch, other.revision}
	for index := range mine {
		if mine[index] != theirs[index] {
			return mine[index] < theirs[index]
		}
	}
	return false
}

type releaseManifest struct {
	Version string `json:"version"`
}

// updateGate knows whether a newer enterprise build has been released. While
// one has, this build must not connect: the user has to install the new build
// first.
//
// The gate only ever learns from a definite answer. When the manifest cannot
// be read it keeps what it knew, so an unreachable download host does not take
// the fleet offline. The policy server refuses outdated builds on its own,
// which is what makes the rule hold for a build that never asks.
type updateGate struct {
	manifestURL string
	current     string
	httpClient  *http.Client
	now         func() time.Time

	mu        sync.RWMutex
	required  string
	checkedAt time.Time
}

func newUpdateGate(current string, httpClient *http.Client, now func() time.Time) *updateGate {
	return &updateGate{manifestURL: releaseManifestURL, current: current, httpClient: httpClient, now: now}
}

// requiredVersion returns the release this build must be replaced with, or ""
// when this build may run.
func (g *updateGate) requiredVersion() string {
	if g == nil {
		return ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.required
}

// denial returns the error a connection attempt gets while an update is
// required, or nil. The text is what the user sees.
func (g *updateGate) denial() error {
	required := g.requiredVersion()
	if required == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s: this NetBird client (%s) is out of date and cannot connect. Install %s from %s",
		errUpdateRequired, g.current, required, releaseBaseURL)
}

// refuseOutdated records that the policy server refused this build as outdated.
func (g *updateGate) refuseOutdated() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.required == "" {
		g.required = latestRelease
	}
}

// refreshIfDue reads the release manifest at most once per check interval.
func (g *updateGate) refreshIfDue(ctx context.Context) {
	if g == nil {
		return
	}
	now := g.now()
	g.mu.Lock()
	due := g.checkedAt.IsZero() || now.Sub(g.checkedAt) >= releaseCheckInterval
	if due {
		g.checkedAt = now
	}
	g.mu.Unlock()
	if !due {
		return
	}
	if err := g.refresh(ctx); err != nil {
		log.Debugf("enterprise release check failed; keeping the previous result: %v", err)
	}
}

func (g *updateGate) refresh(ctx context.Context) error {
	current, ok := parseBuildVersion(g.current)
	if !ok {
		// A build without the enterprise stamp is a development build. It has
		// no place in the release order, and the policy server does not admit it.
		return nil
	}

	requestCtx, cancel := context.WithTimeout(ctx, policyRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, g.manifestURL, nil)
	if err != nil {
		return fmt.Errorf("create release manifest request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := g.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("request release manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("release manifest returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	if len(body) > maxManifestBodyBytes {
		return fmt.Errorf("release manifest exceeds %d bytes", maxManifestBodyBytes)
	}
	var manifest releaseManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("decode release manifest: %w", err)
	}
	latest, ok := parseBuildVersion(manifest.Version)
	if !ok {
		return fmt.Errorf("release manifest names an unusable version %q", manifest.Version)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if current.olderThan(latest) {
		if g.required != manifest.Version {
			log.Warnf("enterprise release %s is available; this build (%s) may no longer connect", manifest.Version, g.current)
		}
		g.required = manifest.Version
	} else {
		g.required = ""
	}
	return nil
}
