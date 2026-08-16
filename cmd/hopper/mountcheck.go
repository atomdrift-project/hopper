package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

var mountPointProbe = isMountPoint

// validateRequiredMounts makes absence inference conditional on the storage
// topology the operator declared. A plain directory left behind beneath an
// unmounted pool is not equivalent to the mounted dataset and must fail closed.
func validateRequiredMounts(dataRoot string, required []string) error {
	for _, name := range required {
		name = filepath.Clean(strings.TrimSpace(name))
		if name == "." || name == "" || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid required mount %q", name)
		}
		path := filepath.Join(dataRoot, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("required mount %s: %w", path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("required mount %s is not a directory", path)
		}
		mounted, source, err := mountPointProbe(path)
		if err != nil {
			return fmt.Errorf("check required mount %s: %w", path, err)
		}
		if !mounted {
			return fmt.Errorf("required mount %s is not an active mountpoint", path)
		}
		slogMountValidated(path, source)
	}
	return nil
}

func slogMountValidated(path, source string) {
	// Kept in a helper so mountcheck's platform files stay dependency-free.
	if source == "" {
		return
	}
	// Validation runs at startup and before a six-hour reconcile. Debug keeps
	// the routine recheck quiet while preserving the filesystem identity.
	slog.Debug("required sample mount validated", "path", path, "source", source)
}
