# Sliver Web GUI

A browser-based operator console for the [Sliver](https://github.com/BishopFox/sliver)
C2 framework. The interface is modeled on the SHADOWFORGE teamserver console — a
top time strip, a left sidebar that groups agents by kind, and a tabbed detail
pane — restyled in a zinc dark theme with JetBrains Mono. You get a graphical
operator workflow: a grouped agent list, per-agent interaction (terminal, file
browser, process list, network, screenshots, info), listener management, implant
generation, pivoting and tunnelling (pivot listeners, SOCKS5), and a
collapsible live event log.

It is a thin **bridge**: a small Go server connects to your Sliver server over the
normal operator gRPC channel (mutual TLS + token) and re-exposes a curated subset
of the API as REST + Server-Sent-Events, then serves a single-page web UI. Browsers
can't speak Sliver's mTLS gRPC directly — this bridge is what makes a web UI possible.

```
browser ──HTTP/SSE──> sliver-web-gui ──gRPC/mTLS──> sliver-server
```

## Requirements

**Build:**

| | |
|---|---|
| **Go 1.26.2+** | Hard floor — declared in `go.mod`. |
| network access | To fetch modules (`go.sum` is committed, so builds are verifiable). |

No CGO. **No `npm`/`node` and no frontend build step** — `web/` is hand-written
vanilla HTML/CSS/JS embedded with `//go:embed`, so editing it and re-running
`go build` is the whole workflow. Only two direct module dependencies:
`github.com/bishopfox/sliver` and `google.golang.org/grpc`.

**Runtime:**

| | |
|---|---|
| **Sliver server v1.7.3+** | With the operator/multiplayer gRPC listener up. `go.mod` pins a post-v1.7.3 upstream commit, so the protobufs must be compatible — an older server will not work. |
| **an operator `.cfg`** | Minted against that server, with sufficient permissions. |
| **`sliver-client` on `PATH`** | Drives the whole **Terminal** tab (`console.go`). Without it the typed REST features still work, but every native console command fails. |
| **`sqlite3` CLI** | Stale-listener detection (`listeners_db.go`) shells out to it rather than linking a driver, which is what keeps the build CGO-free. |
| **Linux, running as root** | See below. |

**Install Sliver with the official one-liner** — everything here assumes that
layout (the apt package and source builds are not the supported path):

```
curl https://sliver.sh/install | sudo bash
```

That gives you exactly what this bridge expects, with nothing to adjust:

| it installs | we rely on it for |
|---|---|
| `/usr/local/bin/sliver-client` (with `sliver` as a symlink to it) | the native **Terminal** console |
| `/root/sliver-server` | the unit's `ExecStartPre`, which re-mints the operator config |
| `/etc/systemd/system/sliver.service` | our unit's `After=`/`BindsTo=`/`WantedBy=` |
| operator configs in `~/.sliver-client/configs/` | what `-config` defaults to picking |

Note the server service is **not enabled at boot** by default — that's upstream's
choice, so after a reboot you need `systemctl start sliver`.

If you instead run `sliver-server daemon` by hand with no `sliver.service`, the
bridge itself is unaffected, but `deploy/sliver-web-gui.service` will not start:
`BindsTo=` a unit that doesn't exist is a hard failure. Drop the `After=`,
`BindsTo=` and `WantedBy=sliver.service` lines and use
`WantedBy=multi-user.target` instead.

**This is a co-located sidecar, not a remote client.** It must run on the same
host as `sliver-server`, because it:

- reads the server's SQLite database directly (`-sliver-db`) to find stale listeners;
- deletes per-implant build trees under `<sliver-root>/slivers/` when you rebuild
  a name or delete an implant;
- writes generated implants to a local directory of your choosing.

The systemd unit additionally runs `sliver-server operator` on every start, so
the **server binary** must be present locally too.

## Quick start

```
git clone <url> && cd sliver-web-gui
go build -o sliver-web-gui .

# mint an operator config against your server
sliver-server operator --name webgui --lhost 127.0.0.1 --lport 31337 \
    --permissions all --save ~/.sliver/webgui.cfg

./sliver-web-gui -config ~/.sliver/webgui.cfg
```

Then open <http://127.0.0.1:4443>.

### Changing the port

The default is `127.0.0.1:4443`. Use `-addr` to pick another:

```
./sliver-web-gui -config ~/.sliver/webgui.cfg -addr 127.0.0.1:8443
```

Binding anything other than localhost **requires `-password`** — the server
refuses to start otherwise. See [Security](#security).

### Running it as a service

To install it as a service that starts and stops with the Sliver daemon:

```
sudo ./deploy/install.sh
```

That builds, installs to `/usr/local/bin`, registers
`deploy/sliver-web-gui.service`, and drops a config at
`/etc/default/sliver-web-gui` (mode 0600, never overwritten on reinstall). On a
standard Sliver install there is nothing to edit. The unit re-mints the operator
config on every start, which permanently avoids the CA-mismatch problem
described below, and is bound to `sliver.service` so it comes up and goes down
with the Sliver daemon.

Set the port for the service in `/etc/default/sliver-web-gui` rather than
editing the unit:

```
WEBGUI_ADDR=127.0.0.1:8443
#WEBGUI_OPTS=-password changeme
```

then `systemctl restart sliver-web-gui`.

## Build

```
cd ~/sliver-web-gui
go build -o sliver-web-gui .
```

The web assets are embedded into the binary (`//go:embed web`), so the single
binary is self-contained.

## Run

You need a running Sliver server with the multiplayer/operator gRPC listener up:

```
# in one terminal — start the Sliver multiplayer listener
sliver-server daemon -l 127.0.0.1 -p 31337
```

Then start the GUI with an operator config:

```
./sliver-web-gui -config ~/.sliver-client/configs/<name>.cfg
```

If `-config` is omitted it auto-picks the **most recently modified** `*.cfg` in
`~/.sliver-client/configs/` — i.e. the one you most recently minted, which is the
most likely to still verify against the current server CA. Open
<http://127.0.0.1:4443>.

> **Note on operator configs:** the config's embedded CA must match the *current*
> server database. If you get `certificate signed by unknown authority`, mint a
> fresh one:
> ```
> sliver-server operator --name <you> --lhost 127.0.0.1 --lport 31337 \
>     --permissions all --save ~/.sliver-client/configs/webgui.cfg
> ```

### Flags

| flag | default | meaning |
|------|---------|---------|
| `-config` | first cfg found | operator config (.cfg) used to auth to Sliver |
| `-addr`   | `127.0.0.1:4443` | listen address for the web UI |
| `-password` | *(none)* | HTTP basic-auth password (user: `operator`). **Required** to bind a non-localhost address |
| `-sliver-db` | `<home>/.sliver/sliver.db` | Sliver server sqlite DB, read read-only to detect stale listeners |

## Security

This UI drives a C2 server — anyone who can reach it controls your implants.

- It binds to **localhost only** by default.
- Binding to any other interface **requires `-password`** (the server refuses
  otherwise). Basic auth is sent in clear text, so if you expose it beyond
  localhost, terminate TLS in front of it (e.g. an nginx/caddy reverse proxy) or
  tunnel over SSH: `ssh -L 4443:127.0.0.1:4443 operator@host`.
- The **Terminal**/**Sliver** consoles spawn the real `sliver-client` binary on
  the bridge host on every command (see `console.go`). Anyone who reaches the
  UI gets the full native command set, including host-affecting ones
  (`armory install`, `generate`, etc.) — treat the whole console as privileged.
- **SOCKS5 proxies are hosted on the bridge host itself**, not in a client. A
  started proxy is a real listening socket on this machine and it outlives the
  browser session, so anything else that can reach it reaches the target network
  too — bind it to loopback unless you mean otherwise, and stop proxies when
  you're done.
- Use it only against infrastructure you are authorized to operate.

## Features

| Area | What you can do |
|------|-----------------|
| **Sidebar** | Agents grouped into sessions (green), beacons (blue) and dead (grey), collapsible with counts, filterable, auto-refreshed every 5s; click to select |
| **Dashboard** | Landing view with session/beacon/dead stat tiles |
| **Terminal** | Per-agent console that drives the real `sliver-client` binary (via `console.go`), so it isn't limited to a curated command set — `getsystem`, `make-token`, `procdump`, `hashdump`, `registry`, `execute-shellcode`, `armory`, `profiles`, `loot`, `hosts`, and everything else `sliver-client` supports all work. Sliver commands are the default (`ls`/`ps`/`download`/…, `help` for all); OS **shell** is explicit via `shell <cmd>`, `execute <cmd>`, or `!<cmd>`. Command history persists across page reloads, with tab completion. Each command is a one-shot invocation, so state doesn't persist client-side between commands beyond what Sliver itself tracks (cwd, etc.) — see *Known limitations*. Two commands are intercepted rather than passed through: `socks5` (routed to the bridge-hosted proxy) and `armory install all` (expanded into per-package installs — see *Known limitations*) |
| **Files / Processes / Network** | Browse directories (download/upload/delete/mkdir), `ps`, `ifconfig`+`netstat`. Works on **beacons** too: the bridge waits for the beacon's next check-in and returns the tasked result (so a slow-sleep beacon is slow to browse, but it works) |
| **Pivoting** | Per-agent tab to start/stop TCP or named-pipe pivot listeners on a session, plus **SOCKS5**: start/stop a proxy through the session, with an optional username (a random password is generated and shown). The proxy is hosted by the bridge on its own long-lived gRPC connection, so it survives browser reloads and lives as long as the service — unlike a console-started one. Session-only; beacons are rejected. A server-wide **Pivot graph** view shows every pivoting session and its downstream chained implants |
| **Sliver console** | A sliver-client-style command console backed by the operator gRPC connection: server commands (`sessions`/`beacons`/`jobs`), `use <id>` (or the agent dropdown) to interact, then per-agent commands (`info`/`pwd`/`cd`/`ls`/`ps`/`netstat`/`ifconfig`/`screenshot`/`execute`/`kill`) |
| **Screenshot** | Capture the agent's desktop (GUI hosts only) |
| **Info** | Agent metadata (id, user, host, os/arch, transport, pid, version); live **beacon cadence** editor to reconfigure sleep/jitter on a running beacon; kill button |
| **Listeners** | Start/stop mTLS, HTTP, HTTPS listeners; bind-host **interface→IP dropdown** (incl. `0.0.0.0` all-interfaces, with a warning when you pick a VPN/tunnel IP) and a refresh button; live job table with stale-listener detection/cleanup |
| **Stage listeners** | Host a saved profile's full implant binary on a staging listener for a stager to pull, with optional length prefix |
| **Generate** | Build session/beacon implants (exe / shared lib / shellcode / service) for windows/linux/darwin; single **C2 endpoint** section — a Type dropdown (mTLS/HTTP/HTTPS/**Named Pipe**) with host+port (or a pipe path for named-pipe, to chain through an existing pivot); **sleep/jitter** for beacons; artifact is written to a directory on the bridge host |
| **Profiles** | Save a reusable implant configuration server-side (same target/C2/cadence fields as Generate) so it can be referenced later — e.g. by a stage listener — without re-entering the config each time; list/delete saved profiles |
| **Implants** | Every implant previously built on the server (via Generate or a stage listener), with OS/arch/format/type/C2/staged status, checkbox multi-select and mass delete (also cleans up the leftover per-name build source tree and the artifact file) |
| **Event log** | Collapsible bottom drawer of real-time server events (agent connect/disconnect, jobs) via SSE |

## Known limitations / next steps

- **Beacon interaction fully works.** `execute` results are retrieved by polling
  the beacon task by ID (`GET /api/target/{id}/task/{taskId}`); every other
  interaction (ls/ps/netstat/ifconfig/pwd/cd/download/…) is resolved server-side
  in `Sliver.resolve()`, which waits for the beacon's next check-in and
  unmarshals the tasked result. Browsing a long-sleep beacon is therefore slow
  (one check-in per action) but functional.
- **The native console is one-shot per command, not a persistent PTY.** Each
  Terminal/Sliver-console command spawns a fresh `sliver-client console --rc`
  invocation and exits, so anything whose effect lives on the *client*
  connection — `portfwd`/`rportfwd`, interactive `shell` — doesn't persist
  across commands. Request/response tasking and server-side jobs (listeners,
  pivots, generate, armory) are unaffected. A real persistent, streamed
  `sliver-client` session would be the fix, but isn't built.
  **`socks5` used to be in that broken set** — it appeared to succeed and then
  died with the invocation. It is now a typed feature hosted on the bridge's own
  gRPC connection (`Sliver.StartSocks`) and driven from the session's *Pivoting*
  tab, so it persists; the console command is redirected there.
- **`armory install all` is expanded, not passed through.** The native command
  asks `forms.Confirm("Install N aliases and M extensions?")` before doing
  anything, and this console has no TTY to answer it, so it would exit having
  installed nothing. The bridge instead reads the armory index and issues one
  `armory install <name> -f` per package in a single batched rc script (`-f` is
  required — without it an already-installed package raises an overwrite prompt
  that hangs the same way). It reports distinct packages installed, since shared
  dependencies like `coff-loader` are reinstalled once per dependent.
- The separate **Sliver console** tab (`view-sliver`) is still its own
  hand-coded command dispatcher hitting the typed REST endpoints below, not the
  native `sliver-client` — it covers the common operator/agent commands but not
  the full command set. Only the per-agent **Terminal** tab was switched to the
  native console.
- Downloads are pulled fully into memory (fine for typical files, not for
  multi-GB exfil).
- No UI yet for DNS/WireGuard listeners, live interactive shell, port
  forwarding, Sliver's native `websites` payload hosting, or custom HTTP C2
  profiles (Generate always uses the `default` HTTP C2 config). Loot,
  credentials, the hosts database, and registry/service/token operations are
  reachable via the native Terminal console but have no dedicated panel.
- **Tunnelling is SOCKS5 only.** A ligolo-ng integration was tried and removed
  (it didn't work in practice); route through the bridge-hosted SOCKS5 proxy in
  the Pivoting tab instead. Running ligolo-ng alongside this by hand still works
  fine — the bridge just doesn't drive it.

## Layout

```
main.go           HTTP server, embed, auth middleware, flags
api.go            REST + SSE route handlers
sliver.go         gRPC client wrapper (connect, sessions, files, exec, generate,
                  profiles, stagers, implant builds, pivots, socks5, events)
console.go        drives the real sliver-client binary for native per-agent
                  and server-scope commands (one-shot --rc invocations), plus
                  the `armory install all` expansion
listeners_db.go   stale-listener detection by reading the Sliver sqlite DB directly
tools.go          small host-side helpers: saving a generated implant to disk,
                  running local commands (e.g. sqlite3)
web/              embedded single-page frontend (index.html, app.js, style.css)
                  — no build step, edit and rebuild
deploy/           systemd unit, install.sh, and the env file that sets the
                  listen address (sliver-web-gui.env.example)
```
