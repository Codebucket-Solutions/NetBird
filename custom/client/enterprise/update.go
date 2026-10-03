//go:build enterprise

package enterprise

import (
	"encoding/json"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// releaseBaseURL is where enterprise builds are published. It is shown
	// to the user when the policy server names no archive for this platform.
	releaseBaseURL = "https://netbird-client.download.codebuckets.in"

	errUpdateRequired = "ENTERPRISE_UPDATE_REQUIRED"

	// latestRelease stands in for the version when the policy server's
	// answer did not name one.
	latestRelease = "the latest version"
)

// updateRequired is the body the policy server sends with HTTP 426 to a build
// older than the latest release.
type updateRequired struct {
	RequiredVersion string `json:"requiredVersion"`
	Artifacts       []struct {
		Platform string `json:"platform"`
		URL      string `json:"url"`
	} `json:"artifacts"`
}

// updateGate knows whether the policy server has refused this build as
// outdated. While it has, this build must not connect: the user has to install
// the build the server named first. Engineering Fabric decides which build is
// current and hands out the download link; this process only remembers what
// it was told.
type updateGate struct {
	current string

	mu          sync.RWMutex
	required    string
	downloadURL string
}

func newUpdateGate(current string) *updateGate {
	return &updateGate{current: current}
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
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.required == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s: this NetBird client (%s) is out of date and cannot connect. Install %s from %s",
		errUpdateRequired, g.current, g.required, g.downloadURL)
}

// require records a refusal. The body may be empty or unreadable; the build is
// outdated either way, and the user is then pointed at the download host.
func (g *updateGate) require(body []byte) {
	if g == nil {
		return
	}
	required, downloadURL := latestRelease, releaseBaseURL
	var answer updateRequired
	if err := json.Unmarshal(body, &answer); err == nil {
		if answer.RequiredVersion != "" {
			required = answer.RequiredVersion
		}
		for _, artifact := range answer.Artifacts {
			if artifact.Platform == platformName() && artifact.URL != "" {
				downloadURL = artifact.URL
			}
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.required != required {
		log.Warnf("enterprise release %s is required; this build (%s) may no longer connect", required, g.current)
	}
	g.required = required
	g.downloadURL = downloadURL
}

// clear records that the policy server served this build again.
func (g *updateGate) clear() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.required != "" {
		log.Infof("enterprise policy server accepts this build (%s) again", g.current)
	}
	g.required = ""
	g.downloadURL = ""
}

// platformName matches the artifact names in the release manifest, for
// example windows-amd64.
func platformName() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}
