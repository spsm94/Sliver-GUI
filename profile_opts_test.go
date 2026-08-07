package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The store lives in the Sliver root, which these tests redirect so they never
// touch a real install.
func withTempRoot(t *testing.T) {
	t.Helper()
	t.Setenv("SLIVER_ROOT_DIR", t.TempDir())
}

func TestProfileOptsRoundTrip(t *testing.T) {
	withTempRoot(t)

	if got := getProfileOpts("never-saved"); got.PrependSize {
		t.Errorf("unknown profile returned %+v, want zero value", got)
	}
	if err := setProfileOpts("msf-stager", ProfileOpts{PrependSize: true}); err != nil {
		t.Fatalf("setProfileOpts: %v", err)
	}
	if err := setProfileOpts("plain", ProfileOpts{PrependSize: false}); err != nil {
		t.Fatalf("setProfileOpts: %v", err)
	}
	if !getProfileOpts("msf-stager").PrependSize {
		t.Error("msf-stager lost its prepend-size across a save/load")
	}
	if getProfileOpts("plain").PrependSize {
		t.Error("plain gained a prepend-size it was never given")
	}
}

// A profile deleted and recreated under the same name must not inherit the old
// one's framing — that would silently break a stager built for the new profile.
func TestProfileOptsDeleteClears(t *testing.T) {
	withTempRoot(t)

	if err := setProfileOpts("recycled", ProfileOpts{PrependSize: true}); err != nil {
		t.Fatalf("setProfileOpts: %v", err)
	}
	if err := deleteProfileOpts("recycled"); err != nil {
		t.Fatalf("deleteProfileOpts: %v", err)
	}
	if getProfileOpts("recycled").PrependSize {
		t.Error("prepend-size survived deletion of the profile")
	}
	// Deleting something absent is a no-op, not an error: the profile delete
	// path calls this for every profile, including ones never given settings.
	if err := deleteProfileOpts("never-existed"); err != nil {
		t.Errorf("deleting an absent entry returned %v, want nil", err)
	}
}

// Losing these settings must never block listing or saving a profile, so a
// corrupt file degrades to "no settings" rather than propagating an error.
func TestProfileOptsCorruptFileIsIgnored(t *testing.T) {
	withTempRoot(t)

	root, err := sliverRoot()
	if err != nil {
		t.Fatalf("sliverRoot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, profileOptsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := loadProfileOpts(); len(got) != 0 {
		t.Errorf("loadProfileOpts on corrupt file = %+v, want empty", got)
	}
	// And it must recover: a later write replaces the bad file.
	if err := setProfileOpts("fresh", ProfileOpts{PrependSize: true}); err != nil {
		t.Fatalf("setProfileOpts after corruption: %v", err)
	}
	if !getProfileOpts("fresh").PrependSize {
		t.Error("could not write settings after a corrupt file")
	}
}

// The file records operational detail about payloads; it should not be
// world-readable on a shared host.
func TestProfileOptsFilePermissions(t *testing.T) {
	withTempRoot(t)

	if err := setProfileOpts("p", ProfileOpts{PrependSize: true}); err != nil {
		t.Fatalf("setProfileOpts: %v", err)
	}
	root, _ := sliverRoot()
	info, err := os.Stat(filepath.Join(root, profileOptsFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

// The temp file used for the atomic write must not be left behind.
func TestProfileOptsNoTempLeftovers(t *testing.T) {
	withTempRoot(t)

	for i := 0; i < 3; i++ {
		if err := setProfileOpts("p", ProfileOpts{PrependSize: true}); err != nil {
			t.Fatalf("setProfileOpts: %v", err)
		}
	}
	root, _ := sliverRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != profileOptsFile {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("root contains %v, want just %s", names, profileOptsFile)
	}
}
