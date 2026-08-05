package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"google.golang.org/protobuf/proto"
	"sync"
)

var (
	usedSaveDirs = make(map[string]bool)
	saveDirsLock sync.Mutex
)

func registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/config", hConfig)
	mux.HandleFunc("GET /api/interfaces", hInterfaces)
	mux.HandleFunc("GET /api/browse-dirs", hBrowseDirs)
	mux.HandleFunc("GET /api/sessions", hSessions)
	mux.HandleFunc("GET /api/beacons", hBeacons)
	mux.HandleFunc("GET /api/jobs", hJobs)

	mux.HandleFunc("POST /api/jobs/mtls", hStartMTLS)
	mux.HandleFunc("POST /api/jobs/http", hStartHTTP)
	mux.HandleFunc("DELETE /api/jobs/{id}", hKillJob)
	mux.HandleFunc("GET /api/jobs/stale", hStaleListeners)
	mux.HandleFunc("DELETE /api/jobs/stale/{id}", hRemoveStale)
	mux.HandleFunc("GET /api/stage-listeners", hGetStageListeners)
	mux.HandleFunc("POST /api/stage-listeners", hStartStageListener)

	mux.HandleFunc("POST /api/target/{id}/execute", hExecute)
	mux.HandleFunc("GET /api/target/{id}/task/{taskId}", hExecuteTask)
	mux.HandleFunc("POST /api/target/{id}/execute-assembly", hExecuteAssembly)
	mux.HandleFunc("POST /api/target/{id}/interactive", hInteractive)
	mux.HandleFunc("POST /api/target/{id}/ls", hLs)
	mux.HandleFunc("POST /api/target/{id}/cd", hCd)
	mux.HandleFunc("GET /api/target/{id}/pwd", hPwd)
	mux.HandleFunc("GET /api/target/{id}/ps", hPs)
	mux.HandleFunc("GET /api/target/{id}/netstat", hNetstat)
	mux.HandleFunc("GET /api/target/{id}/ifconfig", hIfconfig)
	mux.HandleFunc("POST /api/target/{id}/download", hDownload)
	mux.HandleFunc("POST /api/target/{id}/upload", hUpload)
	mux.HandleFunc("POST /api/target/{id}/rm", hRm)
	mux.HandleFunc("POST /api/target/{id}/mkdir", hMkdir)
	mux.HandleFunc("GET /api/target/{id}/screenshot", hScreenshot)
	mux.HandleFunc("POST /api/target/{id}/kill", hKill)
	mux.HandleFunc("POST /api/target/{id}/remove", hRemoveBeacon)
	mux.HandleFunc("POST /api/target/{id}/rename", hRename)
	mux.HandleFunc("POST /api/target/{id}/reconfigure", hReconfigure)

	// native Sliver command console (drives the real sliver-client)
	mux.HandleFunc("POST /api/console", hConsole)
	mux.HandleFunc("POST /api/target/{id}/console", hConsole)

	// pivots (session-hosted listeners for routing to unreachable hosts)
	mux.HandleFunc("GET /api/pivots", hPivotGraph)
	mux.HandleFunc("GET /api/target/{id}/pivots", hPivotListeners)
	mux.HandleFunc("POST /api/target/{id}/pivots", hStartPivot)
	mux.HandleFunc("DELETE /api/target/{id}/pivots/{pid}", hStopPivot)

	// socks5 (client-tunnelled proxy, hosted by this bridge — see sliver.go)
	mux.HandleFunc("GET /api/socks", hSocksList)
	mux.HandleFunc("POST /api/target/{id}/socks", hStartSocks)
	mux.HandleFunc("DELETE /api/socks/{sid}", hStopSocks)

	// ligolo-ng (TUN-based tunneling via an external proxy daemon — see ligolo.go)
	mux.HandleFunc("GET /api/ligolo/status", hLigoloStatus)
	mux.HandleFunc("GET /api/ligolo/agents", hLigoloAgents)
	mux.HandleFunc("GET /api/ligolo/interfaces", hLigoloInterfaces)
	mux.HandleFunc("POST /api/ligolo/interfaces", hLigoloAddInterface)
	mux.HandleFunc("DELETE /api/ligolo/interfaces", hLigoloDeleteInterface)
	mux.HandleFunc("POST /api/ligolo/routes", hLigoloAddRoutes)
	mux.HandleFunc("DELETE /api/ligolo/routes", hLigoloDeleteRoute)
	mux.HandleFunc("GET /api/ligolo/listeners", hLigoloListeners)
	mux.HandleFunc("POST /api/ligolo/listeners", hLigoloAddListener)
	mux.HandleFunc("DELETE /api/ligolo/listeners", hLigoloDeleteListener)
	mux.HandleFunc("POST /api/ligolo/tunnel/{id}", hLigoloStartTunnel)
	mux.HandleFunc("DELETE /api/ligolo/tunnel/{id}", hLigoloStopTunnel)

	mux.HandleFunc("POST /api/generate", hGenerate)

	// implant profiles (saved generate configs)
	mux.HandleFunc("GET /api/profiles", hProfiles)
	mux.HandleFunc("POST /api/profiles", hSaveProfile)
	mux.HandleFunc("DELETE /api/profiles/{name}", hDeleteProfile)

	// stage listeners (raw-TCP handoff of a profile's implant binary to a stager)
	mux.HandleFunc("POST /api/stagers", hStartStager)

	// previously generated implant builds
	mux.HandleFunc("GET /api/implants", hImplants)
	mux.HandleFunc("DELETE /api/implants/{name}", hDeleteImplant)

	mux.HandleFunc("GET /api/events", hEvents)
}

func hConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"operator": sliver.cfg.Operator,
		"server":   fmt.Sprintf("%s:%d", sliver.cfg.LHost, sliver.cfg.LPort),
	})
}

// hInterfaces enumerates the local network interfaces of the bridge host and
// returns each assigned IP with its interface name. This is the same
// interface→IP translation Sliver's own client performs for LHOST completion
// (net.Interfaces); the bridge is normally co-located with the Sliver server,
// so these are the addresses operators bind listeners to / point implants at.
func hInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeErr(w, err, 500)
		return
	}
	type ifAddr struct {
		Name    string `json:"name"`
		IP      string `json:"ip"`
		Version int    `json:"version"` // 4 or 6
		Up      bool   `json:"up"`
	}
	out := []ifAddr{}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		up := i.Flags&net.FlagUp != 0
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ver := 4
			if ip.To4() == nil {
				ver = 6
			}
			out = append(out, ifAddr{Name: i.Name, IP: ip.String(), Version: ver, Up: up})
		}
	}
	// IPv4 first, then by interface name — the order operators expect.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, out)
}

// hBrowseDirs lists the subdirectories of a path on the bridge host, for the
// Generate tab's save-directory picker. It only ever lists directories (never
// file contents) and starts from the operator's home directory when no path
// is given. The bridge already treats the whole console as operator-privileged
// (see README's Security section), so this exposes nothing the operator
// couldn't already reach via the native Terminal's `shell ls` / `cd`.
func hBrowseDirs(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = home
		} else {
			path = "/"
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		writeErr(w, err, 400)
		return
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		writeErr(w, err, 400)
		return
	}
	type dirEntry struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	dirs := []dirEntry{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dirs = append(dirs, dirEntry{Name: e.Name(), Path: filepath.Join(abs, e.Name())})
	}
	sort.Slice(dirs, func(i, j int) bool { return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name) })
	parent := filepath.Dir(abs)
	if parent == abs {
		parent = "" // already at filesystem root
	}
	writeJSON(w, map[string]any{"path": abs, "parent": parent, "dirs": dirs})
}

func hSessions(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.Sessions()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, list)
}

func hBeacons(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.Beacons()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, list)
}

func hJobs(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.Jobs()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, list)
}

func hStartMTLS(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Port uint32 `json:"port"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if in.Port == 0 {
		in.Port = 8888
	}
	job, err := sliver.StartMTLS(in.Host, in.Port)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, job)
}

func hStartHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host   string `json:"host"`
		Domain string `json:"domain"`
		Port   uint32 `json:"port"`
		Secure bool   `json:"secure"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if in.Port == 0 {
		if in.Secure {
			in.Port = 443
		} else {
			in.Port = 80
		}
	}
	job, err := sliver.StartHTTP(in.Host, in.Domain, in.Port, in.Secure)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, job)
}

func hKillJob(w http.ResponseWriter, r *http.Request) {
	if err := sliver.KillJob(atoiU32(r.PathValue("id"))); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// hStaleListeners lists persisted listeners in the Sliver DB that have no
// matching running job — records the console can neither see nor clean up.
func hStaleListeners(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.StaleListeners()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if list == nil {
		list = []persistedListener{}
	}
	writeJSON(w, list)
}

// hRemoveStale deletes a stale listener's DB rows. It refuses to remove a
// currently-running job (enforced in RemoveStaleListener).
func hRemoveStale(w http.ResponseWriter, r *http.Request) {
	if err := sliver.RemoveStaleListener(atoiU32(r.PathValue("id"))); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hGetStageListeners(w http.ResponseWriter, r *http.Request) {
	jobs, err := sliver.Jobs()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	var stageListeners []map[string]any
	for _, j := range jobs {
		if j.Name == "stage" {
			stageListeners = append(stageListeners, map[string]any{
				"JobID":   j.ID,
				"URL":     j.Description,
				"Profile": j.Name,
			})
		}
	}
	if stageListeners == nil {
		stageListeners = []map[string]any{}
	}
	writeJSON(w, stageListeners)
}

func hStartStageListener(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL         string `json:"url"`
		Profile     string `json:"profile"`
		PrependSize bool   `json:"prependSize"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.URL) == "" {
		writeErr(w, fmt.Errorf("URL required"), 400)
		return
	}
	if strings.TrimSpace(in.Profile) == "" {
		writeErr(w, fmt.Errorf("profile required"), 400)
		return
	}
	cmd := fmt.Sprintf("stage-listener --url %s --profile %s", in.URL, in.Profile)
	if in.PrependSize {
		cmd += " --prepend-size"
	}
	_, err := runSliverConsole("", cmd)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hExecute(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cmd string `json:"cmd"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.Cmd) == "" {
		writeErr(w, fmt.Errorf("empty command"), 400)
		return
	}
	resp, err := sliver.ExecuteShell(r.PathValue("id"), in.Cmd)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	// Beacons task asynchronously: the Execute call returns immediately with a
	// task ID and no output. The browser polls GET /task/{taskId} until the
	// beacon checks in and the result is available. Sessions run synchronously
	// and carry stdout/stderr inline.
	if resp.Response != nil && resp.Response.Async {
		writeJSON(w, map[string]any{
			"async":  true,
			"taskId": resp.Response.TaskID,
			"state":  "pending",
		})
		return
	}
	writeJSON(w, map[string]any{
		"async":  false,
		"status": resp.Status,
		"pid":    resp.Pid,
		"stdout": string(resp.Stdout),
		"stderr": string(resp.Stderr),
	})
}

// hExecuteTask returns the result of an async beacon task by ID. While the
// beacon has not yet checked in, state is "pending"/"sent" and done is false;
// once "completed", the stored response is decoded back into the execute result
// so the same stdout/stderr shape is returned as the synchronous path.
func hExecuteTask(w http.ResponseWriter, r *http.Request) {
	task, err := sliver.BeaconTaskContent(r.PathValue("taskId"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if task.State != "completed" {
		writeJSON(w, map[string]any{"done": false, "state": task.State})
		return
	}
	ex := &sliverpb.Execute{}
	if len(task.Response) > 0 {
		if err := proto.Unmarshal(task.Response, ex); err != nil {
			writeErr(w, fmt.Errorf("decode task response: %w", err), 502)
			return
		}
	}
	writeJSON(w, map[string]any{
		"done":   true,
		"state":  task.State,
		"status": ex.Status,
		"pid":    ex.Pid,
		"stdout": string(ex.Stdout),
		"stderr": string(ex.Stderr),
	})
}

// hExecuteAssembly reads a .NET assembly from a path on the bridge host (the
// operator machine — same model as sliver-client, which loads the file locally)
// and runs it in memory on the target.
func hExecuteAssembly(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path    string `json:"path"`
		Args    string `json:"args"`
		Process string `json:"process"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.Path) == "" {
		writeErr(w, fmt.Errorf("assembly path (on the bridge host) is required"), 400)
		return
	}
	data, err := os.ReadFile(in.Path)
	if err != nil {
		writeErr(w, fmt.Errorf("read assembly %q: %w", in.Path, err), 400)
		return
	}
	resp, err := sliver.ExecuteAssembly(r.PathValue("id"), data, strings.Fields(in.Args), in.Process)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"output": string(resp.Output), "bytes": len(resp.Output)})
}

func hInteractive(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Interactive(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{
		"ok":    true,
		"async": resp.Response != nil && resp.Response.Async,
	})
}

func hLs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	_ = decode(r, &in)
	resp, err := sliver.Ls(r.PathValue("id"), in.Path)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hCd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	resp, err := sliver.Cd(r.PathValue("id"), in.Path)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hPwd(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Pwd(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hPs(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Ps(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hNetstat(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Netstat(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hIfconfig(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Ifconfig(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, resp)
}

func hDownload(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	resp, err := sliver.Download(r.PathValue("id"), in.Path)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{
		"path":   resp.Path,
		"exists": resp.Exists,
		"isDir":  resp.IsDir,
		"size":   len(resp.Data),
		"data":   base64.StdEncoding.EncodeToString(resp.Data),
	})
}

func hUpload(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
		Data string `json:"data"` // base64
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil {
		writeErr(w, err, 400)
		return
	}
	resp, err := sliver.Upload(r.PathValue("id"), in.Path, raw)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"path": resp.Path})
}

func hRm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	resp, err := sliver.Rm(r.PathValue("id"), in.Path, in.Recursive)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"path": resp.Path})
}

func hMkdir(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	resp, err := sliver.Mkdir(r.PathValue("id"), in.Path)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"path": resp.Path})
}

func hScreenshot(w http.ResponseWriter, r *http.Request) {
	resp, err := sliver.Screenshot(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"data": base64.StdEncoding.EncodeToString(resp.Data)})
}

func hKill(w http.ResponseWriter, r *http.Request) {
	if err := sliver.Kill(r.PathValue("id")); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hRename(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		writeErr(w, fmt.Errorf("name is required"), 400)
		return
	}
	if err := sliver.Rename(r.PathValue("id"), in.Name); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hRemoveBeacon(w http.ResponseWriter, r *http.Request) {
	if err := sliver.RemoveBeacon(r.PathValue("id")); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hReconfigure(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interval int64 `json:"interval"` // seconds
		Jitter   int64 `json:"jitter"`   // seconds
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if in.Interval < 0 || in.Jitter < 0 {
		writeErr(w, fmt.Errorf("interval and jitter must be non-negative"), 400)
		return
	}
	resp, err := sliver.Reconfigure(r.PathValue("id"), in.Interval, in.Jitter)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{
		"ok":    true,
		"async": resp.Response != nil && resp.Response.Async,
	})
}

// hConsole runs one native Sliver command via the real sliver-client. When the
// route carries an {id} the command runs against that session/beacon (`use id`
// first); at /api/console (no id) it runs at the server scope (armory, profiles,
// jobs, generate, ...). The captured, cleaned console output is returned as-is.
func hConsole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cmd string `json:"cmd"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.Cmd) == "" {
		writeErr(w, fmt.Errorf("empty command"), 400)
		return
	}
	out, err := runSliverConsole(r.PathValue("id"), in.Cmd)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]any{"output": out})
}

// hPivotGraph returns the server-wide pivot session tree.
func hPivotGraph(w http.ResponseWriter, r *http.Request) {
	graph, err := sliver.PivotGraph()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, graph)
}

// hPivotListeners lists the pivot listeners running on a session.
func hPivotListeners(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.PivotListeners(r.PathValue("id"))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if list == nil {
		list = []*sliverpb.PivotListener{}
	}
	writeJSON(w, list)
}

// hStartPivot starts a tcp or named-pipe pivot listener on a session.
func hStartPivot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type     string `json:"type"` // tcp | named-pipe
		Bind     string `json:"bind"`
		AllowAll bool   `json:"allowAll"` // named-pipe only
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	pl, err := sliver.StartPivot(r.PathValue("id"), in.Type, strings.TrimSpace(in.Bind), in.AllowAll)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, pl)
}

// hStopPivot stops a pivot listener (by listener ID) on a session.
func hStopPivot(w http.ResponseWriter, r *http.Request) {
	if err := sliver.StopPivot(r.PathValue("id"), atoiU32(r.PathValue("pid"))); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// hSocksList lists the socks5 proxies this bridge is hosting.
func hSocksList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, sliver.SocksList())
}

// hStartSocks opens a socks5 listener on the bridge host, tunnelled through a
// session. The proxy lives in this process, so it persists across browser
// reloads and stops only when removed or when the bridge restarts.
func hStartSocks(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host string `json:"host"`
		Port string `json:"port"`
		User string `json:"user"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	meta, err := sliver.StartSocks(r.PathValue("id"),
		strings.TrimSpace(in.Host), strings.TrimSpace(in.Port), strings.TrimSpace(in.User))
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, meta)
}

// hStopSocks closes a socks5 proxy and every connection through it.
func hStopSocks(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("sid"), 10, 64)
	if err != nil {
		writeErr(w, fmt.Errorf("bad socks id %q", r.PathValue("sid")), 400)
		return
	}
	if err := sliver.StopSocks(id); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- ligolo-ng ----
// These are thin passthroughs to the proxy's API. Keeping them server-side
// holds the JWT in the bridge and avoids ligolo's CORS allowlist, which only
// permits its own web UI origin by default.

// hLigoloStatus reports whether ligolo is configured and reachable, so the GUI
// can show a useful message instead of a wall of failed requests.
func hLigoloStatus(w http.ResponseWriter, r *http.Request) {
	if !ligolo.Configured() {
		writeJSON(w, map[string]any{"configured": false, "ok": false,
			"error": "not configured — restart sliver-web-gui with -ligolo-url and -ligolo-pass"})
		return
	}
	if err := ligolo.Ping(); err != nil {
		writeJSON(w, map[string]any{"configured": true, "ok": false, "url": ligolo.base, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"configured": true, "ok": true, "url": ligolo.base})
}

func hLigoloAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := ligolo.Agents()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if agents == nil {
		agents = []LigoloAgent{}
	}
	writeJSON(w, agents)
}

func hLigoloInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := ligolo.Interfaces()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, ifaces)
}

func hLigoloAddInterface(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	name := strings.TrimSpace(in.Interface)
	if name == "" {
		writeErr(w, fmt.Errorf("interface name is required"), 400)
		return
	}
	if err := ligolo.AddInterface(name); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloDeleteInterface(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if err := ligolo.DeleteInterface(strings.TrimSpace(in.Interface)); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloAddRoutes(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
		Routes    string `json:"routes"` // comma or space separated CIDRs
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	routes := strings.FieldsFunc(in.Routes, func(c rune) bool { return c == ',' || c == ' ' || c == '\n' })
	for i := range routes {
		routes[i] = strings.TrimSpace(routes[i])
	}
	if len(routes) == 0 {
		writeErr(w, fmt.Errorf("at least one CIDR is required (e.g. 10.10.0.0/16)"), 400)
		return
	}
	if err := ligolo.AddRoutes(strings.TrimSpace(in.Interface), routes); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloDeleteRoute(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
		Route     string `json:"route"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if err := ligolo.DeleteRoute(strings.TrimSpace(in.Interface), strings.TrimSpace(in.Route)); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloListeners(w http.ResponseWriter, r *http.Request) {
	list, err := ligolo.Listeners()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if list == nil {
		list = []LigoloListener{}
	}
	writeJSON(w, list)
}

func hLigoloAddListener(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentID      int    `json:"agentId"`
		Network      string `json:"network"`
		ListenerAddr string `json:"listenerAddr"`
		RedirectAddr string `json:"redirectAddr"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if in.Network == "" {
		in.Network = "tcp"
	}
	if err := ligolo.AddListener(in.AgentID, in.Network,
		strings.TrimSpace(in.ListenerAddr), strings.TrimSpace(in.RedirectAddr)); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloDeleteListener(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentID    int `json:"agentId"`
		ListenerID int `json:"listenerId"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if err := ligolo.DeleteListener(in.AgentID, in.ListenerID); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloStartTunnel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, fmt.Errorf("bad agent id %q", r.PathValue("id")), 400)
		return
	}
	var in struct {
		Interface string `json:"interface"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.Interface) == "" {
		writeErr(w, fmt.Errorf("interface is required — create one first"), 400)
		return
	}
	if err := ligolo.StartTunnel(id, strings.TrimSpace(in.Interface)); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hLigoloStopTunnel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, fmt.Errorf("bad agent id %q", r.PathValue("id")), 400)
		return
	}
	if err := ligolo.StopTunnel(id); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func hGenerate(w http.ResponseWriter, r *http.Request) {
	var opts GenerateOptions
	if err := decode(r, &opts); err != nil {
		writeErr(w, err, 400)
		return
	}
	if opts.OS == "" {
		opts.OS = "windows"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	if opts.Interval == 0 {
		opts.Interval = 60
	}
	if err := validateC2Opts(opts); err != nil {
		writeErr(w, err, 400)
		return
	}
	// The artifact is always written to a directory on the bridge host; it is
	// never streamed back to the browser. A save directory is therefore required.
	dir := strings.TrimSpace(opts.SaveDir)
	if dir == "" {
		writeErr(w, fmt.Errorf("save directory is required; the artifact is written to disk, not downloaded"), 400)
		return
	}
	// Auto-replace an existing build of the same name so the operator can reuse a
	// name (e.g. to change the callback port). Sliver enforces unique build names
	// and never cleans the per-name build tree before rebuilding, so without this
	// a repeat name fails in the DB ("UNIQUE") or the compiler ("rename import
	// dir: target exists: .../<name>/src/..."). DeleteImplantBuild frees the name
	// and removes the artifact; it leaves the source tree, so we remove that too.
	if name := strings.TrimSpace(opts.Name); name != "" {
		if err := sliver.DeleteBuild(name); err != nil {
			log.Printf("generate: pre-delete build %q (ignored): %v", name, err)
		}
		if err := removeBuildTree(opts.OS, opts.Arch, name); err != nil {
			log.Printf("generate: remove stale build tree for %q (ignored): %v", name, err)
		}
	}
	resp, err := sliver.Generate(opts)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	savedPath, err := saveArtifact(dir, resp.File.Name, resp.File.Data)
	if err != nil {
		writeErr(w, err, 400)
		return
	}
	writeJSON(w, map[string]any{
		"name":      resp.File.Name,
		"size":      len(resp.File.Data),
		"savedPath": savedPath,
	})
}

// validateC2Opts enforces the C2 endpoint fields shared by Generate and
// SaveProfile: a host (or, for named-pipe, a pipe path) is always required; a
// port is required for every type except named-pipe, which has none.
func validateC2Opts(opts GenerateOptions) error {
	if strings.TrimSpace(opts.C2Host) == "" {
		if opts.C2Type == "named-pipe" {
			return fmt.Errorf("pipe path is required")
		}
		return fmt.Errorf("C2 host is required")
	}
	if opts.C2Type != "named-pipe" && opts.C2Port == 0 {
		return fmt.Errorf("C2 port is required")
	}
	return nil
}

// ---- implant profiles (saved generate configs) ----

func hProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.Profiles()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	if list == nil {
		list = []*clientpb.ImplantProfile{}
	}
	writeJSON(w, list)
}

func hSaveProfile(w http.ResponseWriter, r *http.Request) {
	var opts GenerateOptions
	if err := decode(r, &opts); err != nil {
		writeErr(w, err, 400)
		return
	}
	if opts.OS == "" {
		opts.OS = "windows"
	}
	if opts.Arch == "" {
		opts.Arch = "amd64"
	}
	if opts.Interval == 0 {
		opts.Interval = 60
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		writeErr(w, fmt.Errorf("profile name is required"), 400)
		return
	}
	if err := validateC2Opts(opts); err != nil {
		writeErr(w, err, 400)
		return
	}
	profile, err := sliver.SaveProfile(name, opts)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, profile)
}

func hDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := sliver.DeleteProfile(r.PathValue("name")); err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- stage listeners ----

func hStartStager(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host     string `json:"host"`
		Port     uint32 `json:"port"`
		Profile  string `json:"profile"`
		AESKey   string `json:"aesKey"`
		AESIv    string `json:"aesIv"`
		RC4Key   string `json:"rc4Key"`
		Compress string `json:"compress"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, err, 400)
		return
	}
	if strings.TrimSpace(in.Profile) == "" {
		writeErr(w, fmt.Errorf("profile is required"), 400)
		return
	}
	if in.Port == 0 {
		writeErr(w, fmt.Errorf("port is required"), 400)
		return
	}
	job, err := sliver.StartStageListener(in.Host, in.Port, in.Profile, in.AESKey, in.AESIv, in.RC4Key, in.Compress)
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, job)
}

// ---- implant builds (previously generated artifacts) ----

func hImplants(w http.ResponseWriter, r *http.Request) {
	list, err := sliver.Builds()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	writeJSON(w, list)
}

// hDeleteImplant removes a build's DB record/artifact, its leftover source
// tree, and any saved artifact files matching the build name.
func hDeleteImplant(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	builds, err := sliver.Builds()
	if err != nil {
		writeErr(w, err, 502)
		return
	}
	var goos, goarch string
	for _, b := range builds {
		if b.Name == name {
			goos, goarch = b.Config.GOOS, b.Config.GOARCH
			break
		}
	}
	if err := sliver.DeleteBuild(name); err != nil {
		writeErr(w, err, 502)
		return
	}
	if goos != "" {
		if err := removeBuildTree(goos, goarch, name); err != nil {
			log.Printf("delete implant: remove build tree for %q (ignored): %v", name, err)
		}
	}
	if err := deleteArtifactFiles(name); err != nil {
		log.Printf("delete implant: remove artifact files for %q (ignored): %v", name, err)
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// removeBuildTree deletes Sliver's per-name source build directory
// (<sliver-root>/slivers/<os>/<arch>/<name>). Sliver reuses this directory
// across rebuilds of the same implant name and never clears it, so a stale tree
// from a prior build breaks the next one during dependency extraction. The web
// GUI runs as the same user as the server (root) on the same host, so it can
// remove the directory directly. Resolves the root dir the way the server does:
// $SLIVER_ROOT_DIR, else <home>/.sliver.
func removeBuildTree(goos, goarch, name string) error {
	root := os.Getenv("SLIVER_ROOT_DIR")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			if u, uerr := user.Current(); uerr == nil {
				home = u.HomeDir
			}
		}
		if home == "" {
			return fmt.Errorf("cannot resolve sliver root dir")
		}
		root = filepath.Join(home, ".sliver")
	}
	// filepath.Base mirrors how the server derives the dir name, and guards
	// against a name containing path separators escaping the slivers tree.
	dir := filepath.Join(root, "slivers", goos, goarch, filepath.Base(name))
	return os.RemoveAll(dir)
}

// hEvents streams Sliver server events to the browser as Server-Sent Events.
func hEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, fmt.Errorf("streaming unsupported"), 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	stream, err := sliver.Events(r.Context())
	if err != nil {
		writeErr(w, err, 502)
		return
	}

	// heartbeat keeps proxies from closing the idle connection
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			ev, err := stream.Recv()
			if err != nil {
				return
			}
			payload := map[string]any{"type": ev.EventType}
			if ev.Session != nil {
				payload["session"] = ev.Session
			}
			if ev.Job != nil {
				payload["job"] = ev.Job
			}
			if len(ev.Data) > 0 && len(ev.Data) < 512 {
				payload["data"] = string(ev.Data)
			}
			if ev.Err != "" {
				payload["err"] = ev.Err
			}
			sendSSE(w, flusher, payload)
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func sendSSE(w http.ResponseWriter, f http.Flusher, v any) {
	b, err := marshalJSON(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	f.Flush()
}
