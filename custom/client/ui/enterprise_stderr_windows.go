//go:build enterprise && windows

package main

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// stderrLogName is where a UI started without a console writes what would
// otherwise be lost: the Wails runtime reports a fatal error on stderr, and
// Explorer, the installer, and autostart give a windowsgui process no
// standard handles at all. Logrus output is unaffected; it goes where
// --log-file says.
const (
	stderrLogName     = "netbird-ui.stderr.log"
	stderrLogMaxBytes = 1 << 20
)

func init() {
	if hasStandardHandle(windows.STD_ERROR_HANDLE) {
		return
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	directory := filepath.Join(base, "netbird")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return
	}
	path := filepath.Join(directory, stderrLogName)
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > stderrLogMaxBytes {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return
	}
	os.Stderr = file
	os.Stdout = file
	log.SetOutput(file)
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(file.Fd()))
	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(file.Fd()))
}

func hasStandardHandle(kind uint32) bool {
	handle, err := windows.GetStdHandle(kind)
	return err == nil && handle != 0 && handle != windows.InvalidHandle
}
