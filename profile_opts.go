package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
)

// Bridge-side settings that belong to a profile from the operator's point of
// view but that Sliver has nowhere to put.
//
// A saved profile is an ImplantProfile wrapping an ImplantConfig. PrependSize
// is a field of GenerateStageReq — the stage-listener request — not of
// ImplantConfig, so the server cannot persist it against a profile no matter
// how it is sent. It is nonetheless a property *of the profile* in practice: a
// profile built to feed an msfvenom `custom/*` stager always needs the 4-byte
// length prefix, and one feeding a stager that doesn't expect it never does.
// Getting it wrong is not a soft failure — the stager reads the wrong bytes and
// the stage never runs.
//
// So the bridge remembers it per profile name and pre-applies it whenever a
// stage listener is started from that profile.

// profileOptsFile is where the map is persisted. It lives in the Sliver root
// (same directory the server owns) so it survives service restarts and package
// upgrades of the bridge binary.
const profileOptsFile = "webgui-profile-opts.json"

// ProfileOpts holds the per-profile settings the bridge tracks itself.
type ProfileOpts struct {
	// PrependSize prefixes the stage with its 4-byte length, as Metasploit's
	// custom/* payloads require.
	PrependSize bool `json:"prependSize"`
}

var profileOptsMu sync.Mutex

// sliverRoot resolves the server's root directory the way the server does:
// $SLIVER_ROOT_DIR, else <home>/.sliver.
func sliverRoot() (string, error) {
	if root := os.Getenv("SLIVER_ROOT_DIR"); root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if u, uerr := user.Current(); uerr == nil {
			home = u.HomeDir
		}
	}
	if home == "" {
		return "", fmt.Errorf("cannot resolve sliver root dir")
	}
	return filepath.Join(home, ".sliver"), nil
}

// loadProfileOpts reads the whole map. A missing or unparseable file yields an
// empty map rather than an error: these are conveniences layered on top of the
// server's own state, and losing them must never block listing or saving a
// profile.
func loadProfileOpts() map[string]ProfileOpts {
	out := map[string]ProfileOpts{}
	root, err := sliverRoot()
	if err != nil {
		return out
	}
	data, err := os.ReadFile(filepath.Join(root, profileOptsFile))
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]ProfileOpts{}
	}
	return out
}

// saveProfileOpts writes the map back, atomically — a torn write would be read
// back as unparseable JSON and silently reset every profile's setting.
func saveProfileOpts(m map[string]ProfileOpts) error {
	root, err := sliverRoot()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	final := filepath.Join(root, profileOptsFile)
	tmp, err := os.CreateTemp(root, profileOptsFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), final)
}

// setProfileOpts records the settings for one profile.
func setProfileOpts(name string, opts ProfileOpts) error {
	profileOptsMu.Lock()
	defer profileOptsMu.Unlock()
	m := loadProfileOpts()
	m[name] = opts
	return saveProfileOpts(m)
}

// getProfileOpts returns the settings for one profile, zero-valued if unknown.
func getProfileOpts(name string) ProfileOpts {
	profileOptsMu.Lock()
	defer profileOptsMu.Unlock()
	return loadProfileOpts()[name]
}

// deleteProfileOpts drops a profile's settings, so a deleted-and-recreated
// profile doesn't silently inherit the old one's framing.
func deleteProfileOpts(name string) error {
	profileOptsMu.Lock()
	defer profileOptsMu.Unlock()
	m := loadProfileOpts()
	if _, ok := m[name]; !ok {
		return nil
	}
	delete(m, name)
	return saveProfileOpts(m)
}
