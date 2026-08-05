// Command sliver-web-gui is a browser-based operator console for the Sliver C2
// framework. It connects to a Sliver server using a standard operator config
// (mTLS + token) and serves a Cobalt-Strike-style web UI over HTTP.
package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

var sliver *Sliver
var ligolo *Ligolo

func main() {
	defaultCfg := defaultConfigPath()
	configPath := flag.String("config", defaultCfg, "path to Sliver operator config (.cfg)")
	addr := flag.String("addr", "127.0.0.1:4443", "listen address for the web UI")
	password := flag.String("password", "", "HTTP basic-auth password (user: operator). Required to bind non-localhost")
	dbPath := flag.String("sliver-db", defaultSliverDBPath(), "path to the Sliver server sqlite DB (enables stale-listener detection)")
	ligoloURL := flag.String("ligolo-url", "", "ligolo-ng proxy API base URL (e.g. http://127.0.0.1:8080) — enables the Ligolo tab")
	ligoloUser := flag.String("ligolo-user", "ligolo", "ligolo-ng API username")
	ligoloPass := flag.String("ligolo-pass", "", "ligolo-ng API password")
	flag.Parse()
	sliverDB = *dbPath
	operatorConfigPath = *configPath // reused by the native sliver-client console
	ligolo = NewLigolo(*ligoloURL, *ligoloUser, *ligoloPass)
	if ligolo.Configured() {
		log.Printf("ligolo-ng API configured at %s (user %q)", *ligoloURL, *ligoloUser)
	}

	if *configPath == "" {
		log.Fatal("no operator config found; pass -config /path/to/operator.cfg")
	}
	if !isLoopback(*addr) && *password == "" {
		log.Fatal("refusing to bind a non-localhost address without -password (this UI controls a C2 server)")
	}

	log.Printf("connecting to Sliver using %s ...", *configPath)
	s, err := Connect(*configPath)
	if err != nil {
		log.Fatalf("failed to connect to Sliver: %v", err)
	}
	defer s.Close()
	sliver = s
	log.Printf("connected as operator %q -> %s:%d", s.cfg.Operator, s.cfg.LHost, s.cfg.LPort)

	sub, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	registerAPI(mux)

	handler := auth(*password, mux)
	log.Printf("Sliver Web GUI listening on http://%s  (operator: %s)", *addr, s.cfg.Operator)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal(err)
	}
}

// ---- middleware & helpers ----

func auth(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if password != "" {
			_, pass, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Sliver Web GUI"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopback(addr string) bool {
	host := addr
	if h, _, err := splitHostPort(addr); err == nil {
		host = h
	}
	return host == "" || host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func splitHostPort(addr string) (host, port string, err error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", nil
	}
	return addr[:i], addr[i+1:], nil
}

func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(home, ".sliver-client", "configs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// Pick the most recently modified .cfg. Operators mint a fresh operator
	// config whenever the server CA rotates; the newest one is the most likely
	// to still verify against the current server (an older config fails with
	// "certificate signed by unknown authority").
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cfg") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestTime) {
			newest = filepath.Join(dir, e.Name())
			newestTime = info.ModTime()
		}
	}
	return newest
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func atoiU32(s string) uint32 {
	n, _ := strconv.ParseUint(s, 10, 32)
	return uint32(n)
}
