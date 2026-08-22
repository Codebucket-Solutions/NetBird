//go:build !enterprise

package enterprise

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// LifecycleServer is the narrow seam between NetBird and the enterprise
// decorator. The raw server remains available to the OS service shutdown path.
type LifecycleServer interface {
	proto.DaemonServiceServer
	Start() error
}

// Wrap is deliberately transparent in normal upstream-compatible builds.
func Wrap(_ context.Context, raw LifecycleServer, _ string) LifecycleServer {
	return raw
}
