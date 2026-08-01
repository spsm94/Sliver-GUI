package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// This file gives the web GUI a *native* Sliver command console. Rather than
// re-implementing each command as a typed gRPC call, it drives the real
// `sliver-client` binary the same way an operator would: it feeds an rc script
// (`use <id>` -> the command -> `exit`) to a one-shot console invocation and
// returns the captured output. This means every native Sliver command works —
// getsystem, make-token, procdump, hashdump, registry, execute-shellcode,
// inline-execute-assembly, sideload, armory, profiles, loot, hosts, cat/chmod,
// pivots, etc. — with the exact semantics and output the CLI produces.
//
// Caveat: a one-shot console exits after the command, so commands whose effect
// is bound to the *client* connection (socks5, portfwd/rportfwd, interactive
// `shell`) do not persist — those need a long-lived tunnel (a separate,
// persistent-console feature). Request/response tasking and server-side jobs
// (listeners, pivots, generate, armory) are unaffected.

// operatorConfigPath is the .cfg the bridge authenticates with (set from main).
// The native console reuses it so it speaks as the same operator.
var operatorConfigPath string

// consoleTimeout bounds a single native command. Generous, because armory
// installs and implant builds run long; the browser shows a spinner meanwhile.
const consoleTimeout = 240 * time.Second

var (
	clientHomeOnce sync.Once
	clientHomeDir  string
	clientHomeErr  error
)

// ansiRE strips terminal control sequences (colour, cursor, erase-line) that
// sliver-client emits so the browser sees clean text.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// bannerRE matches the connect/version banner sliver-client prints on every
// start. These lines are distinctive enough that they never collide with real
// command output, so we can drop them wherever they appear.
var bannerRE = regexp.MustCompile(`^(Connecting to .* \.\.\.|\[\*\] (Client|Server) v|\s+Compiled )`)

// clientHome lazily builds an isolated HOME for the child sliver-client whose
// only imported config is the bridge operator config. Isolation matters: if the
// configs dir held more than one .cfg, `sliver-client console` would prompt
// interactively to pick one and hang the one-shot invocation.
func clientHome() (string, error) {
	clientHomeOnce.Do(func() {
		base, err := os.MkdirTemp("", "sliver-webgui-cli-")
		if err != nil {
			clientHomeErr = err
			return
		}
		cfgDir := filepath.Join(base, ".sliver-client", "configs")
		if err := os.MkdirAll(cfgDir, 0o700); err != nil {
			clientHomeErr = err
			return
		}
		clientHomeDir = base
	})
	if clientHomeErr != nil {
		return "", clientHomeErr
	}
	// Re-copy the operator config every time so we stay in step with the server
	// if it re-mints the config (CA rotation): sliver-web-gui restarts with the
	// server, but copying is cheap and makes this self-healing regardless.
	if operatorConfigPath == "" {
		return "", fmt.Errorf("no operator config path configured")
	}
	data, err := os.ReadFile(operatorConfigPath)
	if err != nil {
		return "", fmt.Errorf("read operator config: %w", err)
	}
	dst := filepath.Join(clientHomeDir, ".sliver-client", "configs", "bridge.cfg")
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return "", fmt.Errorf("stage operator config: %w", err)
	}
	return clientHomeDir, nil
}

// runSliverConsole executes a single native Sliver command. If sessionID is
// non-empty the command runs against that session/beacon (via `use`); otherwise
// it runs at the server scope (armory, profiles, jobs, generate, ...).
func runSliverConsole(sessionID, command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("empty command")
	}
	home, err := clientHome()
	if err != nil {
		return "", err
	}

	var rc strings.Builder
	if sessionID != "" {
		rc.WriteString("use ")
		rc.WriteString(sessionID)
		rc.WriteString("\n")
	}
	rc.WriteString(command)
	rc.WriteString("\nexit\n")

	rcFile, err := os.CreateTemp(home, "rc-*.txt")
	if err != nil {
		return "", err
	}
	rcPath := rcFile.Name()
	defer os.Remove(rcPath)
	if _, err := rcFile.WriteString(rc.String()); err != nil {
		rcFile.Close()
		return "", err
	}
	rcFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), consoleTimeout)
	defer cancel()

	c := exec.CommandContext(ctx, "sliver-client", "console", "--rc", rcPath)
	c.Env = append(os.Environ(), "HOME="+home)
	out, runErr := c.CombinedOutput()

	clean := cleanConsoleOutput(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return clean, fmt.Errorf("command timed out after %s", consoleTimeout)
	}
	// sliver-client exits 0 for a normal command run; a non-zero exit usually
	// means a connection/config problem, in which case the captured output is
	// the useful diagnostic. Surface it either way.
	if runErr != nil && clean == "" {
		return "", fmt.Errorf("sliver-client: %v", runErr)
	}
	return clean, nil
}

// cleanConsoleOutput strips ANSI control codes, spinner carriage-return frames,
// and the connect/version banner, then trims surrounding blank lines.
func cleanConsoleOutput(s string) string {
	s = ansiRE.ReplaceAllString(s, "")
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, ln := range lines {
		// A spinner overwrites its line with \r frames; keep only the final one.
		if i := strings.LastIndex(ln, "\r"); i >= 0 {
			ln = ln[i+1:]
		}
		if bannerRE.MatchString(ln) {
			continue
		}
		kept = append(kept, ln)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}
