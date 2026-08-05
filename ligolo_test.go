package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// These tests pin the wire format sliver-web-gui uses against a ligolo-ng 0.8
// proxy, mirroring cmd/proxy/app/daemon.go. They exist because the details are
// easy to get subtly wrong and fail only at runtime against a real proxy:
// the Authorization header is a *bare* JWT, /agents returns a map keyed by id,
// and POST /routes takes an array under "Route".

const testToken = "MOCKTOKEN.abc.def"

// ligoloStub stands in for the proxy. It enforces the same auth rule ligolo's
// middleware does: the header is parsed as a JWT with no "Bearer " stripping.
type ligoloStub struct {
	authCount  int32
	lastBody   map[string]any
	lastAuthHd string
	rejectOnce atomic.Bool // simulate a token the proxy no longer accepts
	handler    func(w http.ResponseWriter, r *http.Request)
}

func newLigoloStub(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*ligoloStub, *httptest.Server, *Ligolo) {
	t.Helper()
	s := &ligoloStub{handler: h}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			atomic.AddInt32(&s.authCount, 1)
			var creds map[string]string
			json.NewDecoder(r.Body).Decode(&creds)
			if creds["Username"] != "ligolo" || creds["Password"] != "s3cret" {
				w.WriteHeader(500)
				io.WriteString(w, `{"error":"invalid credentials"}`)
				return
			}
			io.WriteString(w, `{"token":"`+testToken+`"}`)
			return
		}
		s.lastAuthHd = r.Header.Get("Authorization")
		if s.rejectOnce.Load() {
			s.rejectOnce.Store(false)
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Unauthorized"}`)
			return
		}
		if s.lastAuthHd != testToken {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"Unauthorized"}`)
			return
		}
		if r.Body != nil {
			body := map[string]any{}
			json.NewDecoder(r.Body).Decode(&body)
			s.lastBody = body
		}
		s.handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return s, srv, NewLigolo(srv.URL, "ligolo", "s3cret")
}

func okJSON(payload string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, payload) }
}

// The auth middleware does jwt.Parse(header) directly, so a "Bearer " prefix
// would make every authenticated call 401.
func TestLigoloSendsBareTokenNotBearer(t *testing.T) {
	stub, _, l := newLigoloStub(t, okJSON(`{"message":"pong"}`))
	if err := l.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if stub.lastAuthHd != testToken {
		t.Errorf("Authorization = %q, want the bare token %q", stub.lastAuthHd, testToken)
	}
	if strings.HasPrefix(stub.lastAuthHd, "Bearer ") {
		t.Error("sent a Bearer prefix; ligolo would reject this")
	}
}

// Ligolo tokens last an hour, so the client must not re-authenticate per call.
func TestLigoloCachesToken(t *testing.T) {
	stub, _, l := newLigoloStub(t, okJSON(`{"message":"pong"}`))
	for i := 0; i < 3; i++ {
		if err := l.Ping(); err != nil {
			t.Fatalf("Ping %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&stub.authCount); got != 1 {
		t.Errorf("authenticated %d times, want 1 (token should be cached)", got)
	}
}

// A restarted proxy signs with a new secret, invalidating tokens we still think
// are valid. The client should re-auth and retry rather than surfacing a 401.
func TestLigoloReauthenticatesOn401(t *testing.T) {
	stub, _, l := newLigoloStub(t, okJSON(`{"message":"pong"}`))
	if err := l.Ping(); err != nil {
		t.Fatalf("priming Ping: %v", err)
	}
	stub.rejectOnce.Store(true)
	if err := l.Ping(); err != nil {
		t.Fatalf("Ping after token rejection: %v", err)
	}
	if got := atomic.LoadInt32(&stub.authCount); got != 2 {
		t.Errorf("authenticated %d times, want 2 (one retry after 401)", got)
	}
}

func TestLigoloBadCredentialsReported(t *testing.T) {
	_, srv, _ := newLigoloStub(t, okJSON(`{}`))
	l := NewLigolo(srv.URL, "ligolo", "wrong")
	err := l.Ping()
	if err == nil {
		t.Fatal("expected an error for bad credentials")
	}
	if !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("error %q should mention auth failure", err)
	}
}

// AgentList serializes as a JSON object keyed by the agent's integer id, and
// that key is the id used for tunnel start/stop — it is not inside the value.
func TestLigoloAgentsFlattensMapAndKeepsIDs(t *testing.T) {
	_, _, l := newLigoloStub(t, okJSON(`{
		"3": {"Name":"WEB01","Running":false,"Network":[{"Name":"ens192","Addresses":["172.16.8.20/16"]}]},
		"0": {"Name":"DC01","Running":true,"Interface":"ligolo","Network":[]}
	}`))
	agents, err := l.Agents()
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("got %d agents, want 2", len(agents))
	}
	// Sorted by id so the table order is stable across polls.
	if agents[0].ID != 0 || agents[1].ID != 3 {
		t.Fatalf("ids = %d,%d; want 0,3 in ascending order", agents[0].ID, agents[1].ID)
	}
	if agents[0].Name != "DC01" || !agents[0].Running || agents[0].Interface != "ligolo" {
		t.Errorf("agent 0 decoded wrong: %+v", agents[0])
	}
	if len(agents[1].Network) != 1 || agents[1].Network[0].Addresses[0] != "172.16.8.20/16" {
		t.Errorf("agent 3 network decoded wrong: %+v", agents[1].Network)
	}
}

// POST /routes binds Route as []string; sending a bare string silently fails.
func TestLigoloAddRoutesSendsArray(t *testing.T) {
	stub, _, l := newLigoloStub(t, okJSON(`{"message":"Routes added."}`))
	if err := l.AddRoutes("ligolo", []string{"10.10.0.0/16", "192.168.50.0/24"}); err != nil {
		t.Fatalf("AddRoutes: %v", err)
	}
	if stub.lastBody["Interface"] != "ligolo" {
		t.Errorf("Interface = %v, want ligolo", stub.lastBody["Interface"])
	}
	routes, ok := stub.lastBody["Route"].([]any)
	if !ok {
		t.Fatalf("Route = %#v, want a JSON array", stub.lastBody["Route"])
	}
	if len(routes) != 2 || routes[0] != "10.10.0.0/16" {
		t.Errorf("Route = %v, want both CIDRs in order", routes)
	}
}

func TestLigoloListenerAndTunnelFieldNames(t *testing.T) {
	stub, _, l := newLigoloStub(t, okJSON(`{"message":"ok"}`))

	if err := l.AddListener(7, "tcp", "0.0.0.0:4444", "127.0.0.1:4444"); err != nil {
		t.Fatalf("AddListener: %v", err)
	}
	if stub.lastBody["AgentID"] != float64(7) ||
		stub.lastBody["Network"] != "tcp" ||
		stub.lastBody["ListenerAddr"] != "0.0.0.0:4444" ||
		stub.lastBody["RedirectAddr"] != "127.0.0.1:4444" {
		t.Errorf("listener payload wrong: %#v", stub.lastBody)
	}

	if err := l.StartTunnel(7, "ligolo"); err != nil {
		t.Fatalf("StartTunnel: %v", err)
	}
	if stub.lastBody["Interface"] != "ligolo" {
		t.Errorf("tunnel payload = %#v, want Interface=ligolo", stub.lastBody)
	}
}

// Ligolo reports failures as {"error": "..."} with a 500; that message is far
// more useful than the status line, so it must reach the operator.
func TestLigoloSurfacesProxyErrorMessage(t *testing.T) {
	_, _, l := newLigoloStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		io.WriteString(w, `{"error":"interface ligolo does not exist"}`)
	})
	err := l.StartTunnel(1, "ligolo")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "interface ligolo does not exist" {
		t.Errorf("error = %q, want the proxy's message verbatim", err)
	}
}

func TestLigoloUnconfiguredIsNotAnHTTPCall(t *testing.T) {
	l := NewLigolo("", "", "")
	if l.Configured() {
		t.Error("empty URL should report unconfigured")
	}
	if err := l.Ping(); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("Ping error = %v, want a 'not configured' message", err)
	}
}
