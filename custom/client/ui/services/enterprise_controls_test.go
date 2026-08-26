//go:build enterprise && !android && !ios && !freebsd && !js

package services

import "testing"

func TestEnterpriseControlsFromManagedFields(t *testing.T) {
	tests := []struct {
		name     string
		fields   []string
		disabled bool
	}{
		{name: "absent", fields: []string{"managementURL"}, disabled: false},
		{name: "present", fields: []string{"disableProfiles", "disableQuit"}, disabled: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := enterpriseControlsFromManagedFields(test.fields).DisableQuit; got != test.disabled {
				t.Fatalf("DisableQuit = %t, want %t", got, test.disabled)
			}
		})
	}
}
