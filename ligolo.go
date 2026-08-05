package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This file talks to a ligolo-ng proxy's REST API (ligolo-ng 0.8+, daemon mode).
//
// Ligolo is not a SOCKS proxy: the proxy process creates a TUN interface on the
// host it runs on and routes chosen subnets through a connected agent, so tools
// run unmodified with no proxychains. That means tunnel setup is interface and
// route management on the *bridge host*, which needs root — the sliver-web-gui
// service already runs as root, so it can drive this.
//
// The bridge proxies these calls rather than letting the browser talk to ligolo
// directly: it keeps the JWT server-side and sidesteps ligolo's CORS allowlist,
// which only permits its own web UI's origin by default.

// ligoloTimeout bounds a single call to the ligolo API. Interface and route
// operations touch the kernel, so they are quick; this only guards against a
// wedged proxy.
const ligoloTimeout = 20 * time.Second

// Ligolo is a client for one ligolo-ng proxy's API.
type Ligolo struct {
	base string // e.g. http://127.0.0.1:8080
	user string
	pass string

	mu     sync.Mutex
	token  string
	expiry time.Time
	hc     *http.Client
}

// NewLigolo builds a client. It does not contact the proxy — the proxy is an
// independent daemon that may be started after the bridge.
func NewLigolo(base, user, pass string) *Ligolo {
	return &Ligolo{
		base: strings.TrimRight(base, "/"),
		user: user,
		pass: pass,
		hc:   &http.Client{Timeout: ligoloTimeout},
	}
}

// Configured reports whether a proxy URL was supplied at startup.
func (l *Ligolo) Configured() bool { return l != nil && l.base != "" }

// authenticate exchanges the configured credentials for a JWT. Ligolo signs
// tokens with a 1 hour expiry, so we refresh a minute early rather than waiting
// for a 401 mid-operation.
func (l *Ligolo) authenticate(ctx context.Context) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.token != "" && time.Now().Before(l.expiry) {
		return l.token, nil
	}
	body, _ := json.Marshal(map[string]string{"Username": l.user, "Password": l.pass})
	req, err := http.NewRequestWithContext(ctx, "POST", l.base+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ligolo proxy unreachable at %s: %w", l.base, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ligolo auth failed (%s): %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("ligolo auth returned no token")
	}
	l.token = out.Token
	l.expiry = time.Now().Add(59 * time.Minute)
	return l.token, nil
}

// invalidate drops the cached token so the next call re-authenticates. Used
// when the proxy rejects a token we believed was still valid — it restarts with
// a fresh signing secret, which invalidates every token it ever issued.
func (l *Ligolo) invalidate() {
	l.mu.Lock()
	l.token = ""
	l.mu.Unlock()
}

// do performs an authenticated API call, decoding a JSON response into out (which
// may be nil). It retries once after re-authenticating if the proxy answers 401.
func (l *Ligolo) do(method, path string, in, out any) error {
	if !l.Configured() {
		return fmt.Errorf("ligolo is not configured (start sliver-web-gui with -ligolo-url)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), ligoloTimeout)
	defer cancel()

	send := func() (*http.Response, error) {
		token, err := l.authenticate(ctx)
		if err != nil {
			return nil, err
		}
		var body io.Reader
		if in != nil {
			b, err := json.Marshal(in)
			if err != nil {
				return nil, err
			}
			body = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, l.base+path, body)
		if err != nil {
			return nil, err
		}
		// Ligolo's auth middleware parses the Authorization header as a bare
		// JWT — it does not strip a "Bearer " prefix, so adding one 401s.
		req.Header.Set("Authorization", token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return l.hc.Do(req)
	}

	resp, err := send()
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		l.invalidate()
		if resp, err = send(); err != nil {
			return err
		}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", ligoloErrMsg(raw, resp.Status))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode ligolo response: %w", err)
		}
	}
	return nil
}

// ligoloErrMsg pulls the {"error": ...} field ligolo returns on failure, falling
// back to the HTTP status when the body is not the shape we expect.
func ligoloErrMsg(raw []byte, status string) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return e.Error
	}
	if msg := strings.TrimSpace(string(raw)); msg != "" {
		return msg
	}
	return status
}

// ---- typed operations ----

// LigoloAgent is one connected ligolo agent. The proxy keys these by integer id
// in a map, which is also the id used for tunnel start/stop.
type LigoloAgent struct {
	ID        int              `json:"ID"`
	Name      string           `json:"Name"`
	SessionID string           `json:"SessionID"`
	Interface string           `json:"Interface"`
	Running   bool             `json:"Running"`
	Network   []LigoloNetIface `json:"Network"`
	Listeners []map[string]any `json:"Listeners"`
}

// LigoloNetIface is an interface as seen *on the agent's host* — the addresses
// here are what you would route through the tunnel.
type LigoloNetIface struct {
	Name      string   `json:"Name"`
	Addresses []string `json:"Addresses"`
}

// LigoloListener is a socket the agent binds on its side and relays back.
type LigoloListener struct {
	ListenerID   int32  `json:"ListenerID"`
	AgentID      int    `json:"AgentID"`
	Agent        string `json:"Agent"`
	RemoteAddr   string `json:"RemoteAddr"`
	SessionID    string `json:"SessionID"`
	Network      string `json:"Network"`
	ListenerAddr string `json:"ListenerAddr"`
	RedirectAddr string `json:"RedirectAddr"`
	Online       bool   `json:"Online"`
}

// Ping reports whether the proxy is up and authenticating.
func (l *Ligolo) Ping() error {
	return l.do("GET", "/api/v1/ping", nil, nil)
}

// Agents lists connected agents. The API returns a map keyed by agent id; we
// flatten it to a slice and fill in the ID so the GUI can address them.
func (l *Ligolo) Agents() ([]LigoloAgent, error) {
	var m map[string]LigoloAgent
	if err := l.do("GET", "/api/v1/agents", nil, &m); err != nil {
		return nil, err
	}
	out := make([]LigoloAgent, 0, len(m))
	for id, a := range m {
		fmt.Sscanf(id, "%d", &a.ID)
		out = append(out, a)
	}
	sortLigoloAgents(out)
	return out, nil
}

// Interfaces lists the TUN interfaces ligolo knows about, with their routes.
// The shape is whatever the proxy's config state holds, so it is passed through
// untyped rather than guessed at.
func (l *Ligolo) Interfaces() (any, error) {
	var out any
	if err := l.do("GET", "/api/v1/interfaces", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddInterface creates a TUN interface (requires root on the proxy host).
func (l *Ligolo) AddInterface(name string) error {
	return l.do("POST", "/api/v1/interfaces", map[string]string{"Interface": name}, nil)
}

// DeleteInterface destroys a TUN interface and forgets its config.
func (l *Ligolo) DeleteInterface(name string) error {
	return l.do("DELETE", "/api/v1/interfaces", map[string]string{"Interface": name}, nil)
}

// AddRoutes attaches one or more CIDRs to an interface. Routes added before a
// tunnel is running are applied when it starts.
func (l *Ligolo) AddRoutes(iface string, routes []string) error {
	return l.do("POST", "/api/v1/routes", map[string]any{"Interface": iface, "Route": routes}, nil)
}

// DeleteRoute removes a single CIDR from an interface.
func (l *Ligolo) DeleteRoute(iface, route string) error {
	return l.do("DELETE", "/api/v1/routes", map[string]string{"Interface": iface, "Route": route}, nil)
}

// Listeners lists agent-side listeners across all agents.
func (l *Ligolo) Listeners() ([]LigoloListener, error) {
	var out []LigoloListener
	if err := l.do("GET", "/api/v1/listeners", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddListener binds listenerAddr on the agent and relays it to redirectAddr.
func (l *Ligolo) AddListener(agentID int, network, listenerAddr, redirectAddr string) error {
	return l.do("POST", "/api/v1/listeners", map[string]any{
		"AgentID":      agentID,
		"Network":      network,
		"ListenerAddr": listenerAddr,
		"RedirectAddr": redirectAddr,
	}, nil)
}

// DeleteListener removes an agent-side listener.
func (l *Ligolo) DeleteListener(agentID, listenerID int) error {
	return l.do("DELETE", "/api/v1/listeners", map[string]any{
		"AgentID":    agentID,
		"ListenerID": listenerID,
	}, nil)
}

// StartTunnel binds an agent to a TUN interface, making its routes live.
func (l *Ligolo) StartTunnel(agentID int, iface string) error {
	return l.do("POST", fmt.Sprintf("/api/v1/tunnel/%d", agentID), map[string]string{"Interface": iface}, nil)
}

// StopTunnel tears a tunnel down, leaving the agent connected.
func (l *Ligolo) StopTunnel(agentID int) error {
	return l.do("DELETE", fmt.Sprintf("/api/v1/tunnel/%d", agentID), nil, nil)
}

func sortLigoloAgents(a []LigoloAgent) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j].ID < a[j-1].ID; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
