//go:build enterprise && !android && !ios && !freebsd && !js

package main

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

const enterpriseQuitCheckTimeout = 2 * time.Second

func (t *Tray) enterpriseQuitDisabled() bool {
	if t.svc.Settings == nil {
		log.Error("enterprise quit denied: settings service is unavailable")
		t.notifyError("Quit is disabled because enterprise policy could not be verified.")
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), enterpriseQuitCheckTimeout)
	defer cancel()
	controls, err := t.svc.Settings.GetEnterpriseControls(ctx)
	if err != nil {
		log.Errorf("enterprise quit denied: policy check failed: %v", err)
		t.notifyError("Quit is disabled because enterprise policy could not be verified.")
		return true
	}
	if !controls.DisableQuit {
		return false
	}

	log.Warn("enterprise quit denied by administrator policy")
	t.notifyError("Quit is disabled by your administrator.")
	return true
}
