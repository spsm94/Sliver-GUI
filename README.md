# Sliver Web GUI

A browser-based operator console for the [Sliver](https://github.com/BishopFox/sliver)
C2 framework. The interface is modeled on the SHADOWFORGE teamserver console — a
top time strip, a left sidebar that groups agents by kind, and a tabbed detail
pane — restyled in a zinc dark theme with JetBrains Mono. You get a graphical
operator workflow: a grouped agent list, per-agent interaction (terminal, file
browser, process list, network, screenshots, info), listener management, implant
generation, and a collapsible live event log.

It is a thin **bridge**: a small Go server connects to your Sliver server over the
normal operator gRPC channel (mutual TLS + token) and re-exposes a curated subset
of the API as REST + Server-Sent-Events, then serves a single-page web UI. Browsers
can't speak Sliver's mTLS gRPC directly — this bridge is what makes a web UI possible.

```
browser ──HTTP/SSE──> sliver-web-gui ──gRPC/mTLS──> sliver-server
```

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
- Use it only against infrastructure you are authorized to operate.

## Features

| Area | What you can do |
|------|-----------------|
| **Sidebar** | Agents grouped into sessions (green), beacons (blue) and dead (grey), collapsible with counts, filterable, auto-refreshed every 5s; click to select |
| **Dashboard** | Landing view with session/beacon/dead stat tiles |
| **Terminal** | Per-agent console that drives the real `sliver-client` binary (via `console.go`), so it isn't limited to a curated command set — `getsystem`, `make-token`, `procdump`, `hashdump`, `registry`, `execute-shellcode`, `armory`, `profiles`, `loot`, `hosts`, and everything else `sliver-client` supports all work. Sliver commands are the default (`ls`/`ps`/`download`/…, `help` for all); OS **shell** is explicit via `shell <cmd>`, `execute <cmd>`, or `!<cmd>`. Each command is a one-shot invocation, so state doesn't persist client-side between commands beyond what Sliver itself tracks (cwd, etc.) — see *Known limitations* |
| **Files / Processes / Network** | Browse directories (download/upload/delete/mkdir), `ps`, `ifconfig`+`netstat`. Works on **beacons** too: the bridge waits for the beacon's next check-in and returns the tasked result (so a slow-sleep beacon is slow to browse, but it works) |
| **Pivots** | Per-agent tab to start/stop TCP or named-pipe pivot listeners on a session, and a server-wide **Pivot graph** view showing every pivoting session and its downstream chained implants |
| **Sliver console** | A sliver-client-style command console backed by the operator gRPC connection: server commands (`sessions`/`beacons`/`jobs`), `use <id>` (or the agent dropdown) to interact, then per-agent commands (`info`/`pwd`/`cd`/`ls`/`ps`/`netstat`/`ifconfig`/`screenshot`/`execute`/`kill`) |
| **Screenshot** | Capture the agent's desktop (GUI hosts only) |
| **Info** | Agent metadata (id, user, host, os/arch, transport, pid, version); live **beacon cadence** editor to reconfigure sleep/jitter on a running beacon; kill button |
| **Listeners** | Start/stop mTLS, HTTP, HTTPS listeners; bind-host **interface→IP dropdown** (incl. `0.0.0.0` all-interfaces); live job table with stale-listener detection/cleanup. **Generate stager**: build a saved profile's full implant binary and serve it over a raw-TCP job to a stager on connect, with optional AES/RC4 encryption and compression |
| **Generate** | Build session/beacon implants (exe / shared lib / shellcode / service) for windows/linux/darwin; single **C2 endpoint** section — a Type dropdown (mTLS/HTTP/HTTPS/**Named Pipe**) with host+port (or a pipe path for named-pipe, to chain through an existing pivot); **sleep/jitter** for beacons; artifact is written to a directory on the bridge host |
| **Profiles** | Save a reusable implant configuration server-side (same target/C2/cadence fields as Generate) so it can be referenced later — e.g. by the Listeners tab's stager generator — without re-entering the config each time; list/delete saved profiles |
| **Implants** | Every implant previously built on the server (via Generate or a profile's stager), with OS/arch/format/type/C2/staged status and delete (also cleans up the leftover per-name build source tree) |
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
  connection — `socks5`, `portfwd`/`rportfwd`, interactive `shell` — doesn't
  persist across commands. Request/response tasking and server-side jobs
  (listeners, pivots, generate, armory) are unaffected. A real persistent,
  streamed `sliver-client` session would be the fix, but isn't built.
- The separate **Sliver console** tab (`view-sliver`) is still its own
  hand-coded command dispatcher hitting the typed REST endpoints below, not the
  native `sliver-client` — it covers the common operator/agent commands but not
  the full command set. Only the per-agent **Terminal** tab was switched to the
  native console.
- Downloads are pulled fully into memory (fine for typical files, not for
  multi-GB exfil).
- No UI yet for DNS/WireGuard listeners, live interactive shell, SOCKS5 proxy,
  port forwarding, Sliver's native `websites` payload hosting, or custom HTTP
  C2 profiles (Generate always uses the `default` HTTP C2 config). Loot,
  credentials, the hosts database, and registry/service/token operations are
  reachable via the native Terminal console but have no dedicated panel.

## Layout

```
main.go           HTTP server, embed, auth middleware, flags
api.go            REST + SSE route handlers
sliver.go         gRPC client wrapper (connect, sessions, files, exec, generate,
                  profiles, stagers, implant builds, pivots, events)
console.go        drives the real sliver-client binary for native per-agent
                  and server-scope commands (one-shot --rc invocations)
listeners_db.go   stale-listener detection by reading the Sliver sqlite DB directly
tools.go          small host-side helpers: saving a generated implant to disk,
                  running local commands (e.g. sqlite3)
web/              embedded single-page frontend (index.html, app.js, style.css)
```
