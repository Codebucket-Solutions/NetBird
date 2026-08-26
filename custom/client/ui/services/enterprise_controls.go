//go:build enterprise && !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

const enterpriseDisableQuitField = "disableQuit"

// EnterpriseControls contains UI-only controls projected by the authoritative
// daemon wrapper. The UI never reads the remote policy API directly.
type EnterpriseControls struct {
	DisableQuit bool
}

func (s *Settings) GetEnterpriseControls(ctx context.Context) (EnterpriseControls, error) {
	client, err := s.conn.Client()
	if err != nil {
		return EnterpriseControls{}, err
	}
	response, err := client.GetConfig(ctx, &proto.GetConfigRequest{})
	if err != nil {
		return EnterpriseControls{}, err
	}
	return enterpriseControlsFromManagedFields(response.GetMDMManagedFields()), nil
}

func enterpriseControlsFromManagedFields(fields []string) EnterpriseControls {
	for _, field := range fields {
		if field == enterpriseDisableQuitField {
			return EnterpriseControls{DisableQuit: true}
		}
	}
	return EnterpriseControls{}
}
