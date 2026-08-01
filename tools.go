package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// This file implements small host-side helpers: writing a built implant to
// disk on the bridge host (the machine co-located with the Sliver server —
// the artifact is never streamed back to the browser), and running local
// commands the rest of the GUI shells out to (e.g. sqlite3 for stale-listener
// detection).

// runCmd runs a host command with a 15s timeout, returning combined output and
// an error whose message includes that output.
func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return string(out), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return string(out), nil
}

// saveArtifact writes a generated implant to dir/name on the bridge host,
// creating dir if needed. name is reduced to its base to prevent an implant
// name from escaping the chosen directory.
func saveArtifact(dir, name string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create %q: %w", dir, err)
	}
	name = filepath.Base(name)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "", fmt.Errorf("invalid artifact name %q", name)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	recordSaveDir(dir)
	return path, nil
}

// recordSaveDir tracks directories used for artifact saves so we can clean them up later.
func recordSaveDir(dir string) {
	saveDirsLock.Lock()
	defer saveDirsLock.Unlock()
	usedSaveDirs[dir] = true
}

// deleteArtifactFiles removes all files matching the implant name pattern from tracked save directories.
func deleteArtifactFiles(name string) error {
	saveDirsLock.Lock()
	dirs := make(map[string]bool)
	for d := range usedSaveDirs {
		dirs[d] = true
	}
	saveDirsLock.Unlock()

	var errs []string
	for dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.Contains(entry.Name(), name) {
				path := filepath.Join(dir, entry.Name())
				if err := os.Remove(path); err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", path, err))
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to delete some artifact files: %v", strings.Join(errs, "; "))
	}
	return nil
}
