//go:build !enterprise && !android && !ios && !freebsd && !js

package main

func (t *Tray) enterpriseQuitDisabled() bool {
	return false
}
