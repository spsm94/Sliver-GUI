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
// is bound to the *client* connection (portfwd/rportfwd, interactive `shell`)
// do not persist — those need a long-lived tunnel. Request/response tasking and
// server-side jobs (listeners, pivots, generate, armory) are unaffected.
//
// socks5 was in that broken set: `socks5 start` here appeared to succeed and
// then died with the client. It is now a typed feature hosted on the bridge's
// own persistent gRPC connection (see Sliver.StartSocks) and driven from the
// session's Pivoting tab, so it outlives any one command or browser reload.

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
	return runSliverConsoleScript(sessionID, []string{command}, consoleTimeout)
}

// runSliverConsoleScript runs several commands in *one* sliver-client
// invocation. Batching matters for bulk work: each invocation pays process
// startup plus an armory index read, so a hundred separate calls take an order
// of magnitude longer than one rc script containing a hundred lines.
func runSliverConsoleScript(sessionID string, commands []string, timeout time.Duration) (string, error) {
	if len(commands) == 0 {
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
	for _, cmd := range commands {
		rc.WriteString(cmd)
		rc.WriteString("\n")
	}
	rc.WriteString("exit\n")

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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := exec.CommandContext(ctx, "sliver-client", "console", "--rc", rcPath)
	c.Env = append(os.Environ(), "HOME="+home)
	out, runErr := c.CombinedOutput()

	clean := cleanConsoleOutput(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return clean, fmt.Errorf("command timed out after %s", timeout)
	}
	// sliver-client exits 0 for a normal command run; a non-zero exit usually
	// means a connection/config problem, in which case the captured output is
	// the useful diagnostic. Surface it either way.
	if runErr != nil && clean == "" {
		return "", fmt.Errorf("sliver-client: %v", runErr)
	}
	return clean, nil
}

// ---- armory install all ----
// The native `armory install all` cannot run here: before installing anything it
// calls forms.Confirm("Install N aliases and M extensions?"), and this console
// has no TTY to answer it, so the command exits having done nothing. Installing
// a package *by name* has no such prompt, so we read the index, then issue one
// `armory install <name> -f` per package in a single rc script. -f is required,
// not just convenient: without it an already-installed package raises an
// overwrite prompt that would hang the same way.

// armoryInstallAllTimeout is generous — this downloads every package in the
// index, which is many megabytes over the network.
const armoryInstallAllTimeout = 20 * time.Minute

var armoryInstallAllRE = regexp.MustCompile(`(?i)^armory\s+install\s+all\b`)

// armoryPkgRE pulls the command name out of a row of the armory index table,
// which looks like: " Default   sa-whoami   v0.0.28   Extension   Displays ..."
// Requiring the vN version and the Extension/Alias type keeps it from matching
// the header, separator rules, or the [!] warning lines.
var armoryPkgRE = regexp.MustCompile(`(?m)^\s*\S+\s+(\S+)\s+v\S+\s+(?:Extension|Alias)\s`)

// isArmoryInstallAll reports whether cmd is the bulk install we need to expand.
func isArmoryInstallAll(cmd string) bool {
	return armoryInstallAllRE.MatchString(strings.TrimSpace(cmd))
}

// parseArmoryPackages extracts unique package names from `armory` index output,
// preserving the order they were listed in.
func parseArmoryPackages(index string) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range armoryPkgRE.FindAllStringSubmatch(index, -1) {
		name := m[1]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// runArmoryInstallAll expands the bulk install and reports what happened.
func runArmoryInstallAll() (string, error) {
	index, err := runSliverConsole("", "armory")
	if err != nil {
		return index, fmt.Errorf("could not read the armory index: %w", err)
	}
	names := parseArmoryPackages(index)
	if len(names) == 0 {
		return index, fmt.Errorf("no packages found in the armory index (is the armory reachable?)")
	}

	cmds := make([]string, 0, len(names))
	for _, n := range names {
		cmds = append(cmds, "armory install "+n+" -f")
	}
	out, err := runSliverConsoleScript("", cmds, armoryInstallAllTimeout)

	var b strings.Builder
	fmt.Fprintf(&b, "Expanded `armory install all` into %d individual installs.\n"+
		"(The native command needs an interactive confirmation this console cannot answer.)\n\n", len(names))
	b.WriteString(out)
	if err != nil {
		return b.String(), err
	}
	// Count *distinct* packages: shared dependencies (coff-loader backs every
	// BOF extension) are reinstalled once per dependent, so counting the
	// "Installing" lines would report more installs than packages requested.
	installed := len(parseArmoryInstalled(out))
	fmt.Fprintf(&b, "\n\n--- installed %d distinct packages from %d requested; "+
		"run `extensions list` / `aliases` to confirm. ---", installed, len(names))
	return b.String(), nil
}

// armoryInstalledRE matches the per-package progress line sliver prints, e.g.
//
//	[*] Installing extension 'sa-whoami' (v0.0.28) ...
var armoryInstalledRE = regexp.MustCompile(`Installing (?:extension|alias) '([^']+)'`)

// parseArmoryInstalled returns the distinct package names an install transcript
// reports having installed.
func parseArmoryInstalled(out string) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range armoryInstalledRE.FindAllStringSubmatch(out, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		names = append(names, m[1])
	}
	return names
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
