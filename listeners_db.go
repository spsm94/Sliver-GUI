package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file implements stale-listener detection and cleanup.
//
// Sliver persists every listener as a row in its sqlite DB (listener_jobs plus
// a per-protocol table). On server start it tries to restore those as running
// jobs; if a restore fails (e.g. the bind IP doesn't exist yet because a VPN
// isn't up, or the port is already held by another service) the row is LEFT IN
// THE DB while no job runs. That stranded row still counts against PortInUse(),
// so the operator gets "port N is in use" for a port nothing is listening on.
//
// The operator gRPC API cannot see or remove these: GetJobs only returns the
// in-memory core.Jobs map, and KillJob looks the job up in that same map before
// it ever reaches db.DeleteListener — so a never-started job is unreachable from
// the console. The only way to clear it is to touch the DB directly, which we
// can do because this GUI runs co-located with (and as the same user as) the
// Sliver server. We shell out to the sqlite3 CLI rather than pull in a CGO/Go
// sqlite driver, matching the existing runCmd-based host-helper style.

// sliverDB is the path to the Sliver server's sqlite database, set from a flag
// in main(). Empty disables stale-listener detection.
var sliverDB string

// persistedListener is one row from the Sliver DB's listener_jobs table joined
// with its protocol-specific config table. Running is filled in by comparing
// job_id against the live GetJobs result.
type persistedListener struct {
	JobID   uint32 `json:"job_id"`
	Type    string `json:"type"`
	Host    string `json:"host"`
	Port    uint32 `json:"port"`
	Running bool   `json:"running"`
}

// listenerQuery pulls every persisted listener with its host/port from whichever
// protocol table holds its config. When a persistent job restarts successfully
// the DB's job_id is updated to the new in-memory job ID, so job_id is directly
// comparable to GetJobs IDs.
const listenerQuery = `SELECT lj.job_id AS job_id, lj.type AS type,
COALESCE(h.host, m.host, d.host, '') AS host,
COALESCE(h.port, m.port, d.port, w.port, mp.port, 0) AS port
FROM listener_jobs lj
LEFT JOIN http_listeners h ON h.listener_job_id = lj.id
LEFT JOIN mtls_listeners m ON m.listener_job_id = lj.id
LEFT JOIN dns_listeners d ON d.listener_job_id = lj.id
LEFT JOIN wg_listeners w ON w.listener_job_id = lj.id
LEFT JOIN multiplayer_listeners mp ON mp.listener_job_id = lj.id;`

// defaultSliverDBPath returns <home>/.sliver/sliver.db, the standard location
// for the server's DB (the GUI runs as the same user as the server).
func defaultSliverDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sliver", "sliver.db")
}

// persistedListeners reads all persisted listeners from the Sliver DB. It opens
// the DB read-only so it can never interfere with the running server.
func persistedListeners() ([]persistedListener, error) {
	if sliverDB == "" {
		return nil, fmt.Errorf("sliver DB path not configured")
	}
	if _, err := os.Stat(sliverDB); err != nil {
		return nil, fmt.Errorf("sliver DB not found at %s: %w", sliverDB, err)
	}
	uri := "file:" + sliverDB + "?mode=ro"
	out, err := runCmd("sqlite3", "-json", uri, listenerQuery)
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" { // sqlite3 -json prints nothing for zero rows
		return nil, nil
	}
	var rows []persistedListener
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("parsing listener rows: %w", err)
	}
	return rows, nil
}

// StaleListeners returns persisted listeners that have no matching running job —
// i.e. rows the console can neither see nor clean up.
func (s *Sliver) StaleListeners() ([]persistedListener, error) {
	persisted, err := persistedListeners()
	if err != nil {
		return nil, err
	}
	jobs, err := s.Jobs()
	if err != nil {
		return nil, err
	}
	running := make(map[uint32]bool, len(jobs))
	for _, j := range jobs {
		running[j.ID] = true
	}
	var stale []persistedListener
	for _, p := range persisted {
		if !running[p.JobID] {
			stale = append(stale, p)
		}
	}
	return stale, nil
}

// RemoveStaleListener deletes a stale listener's DB rows, replicating Sliver's
// own db.DeleteListener cascade (the protocol table, then listener_jobs). It
// refuses to touch a job_id that is currently running, so a live listener can
// never be silently de-persisted through this path.
func (s *Sliver) RemoveStaleListener(jobID uint32) error {
	if sliverDB == "" {
		return fmt.Errorf("sliver DB path not configured")
	}
	jobs, err := s.Jobs()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.ID == jobID {
			return fmt.Errorf("job %d is currently running; use Stop instead of removing its record", jobID)
		}
	}
	persisted, err := persistedListeners()
	if err != nil {
		return err
	}
	found := false
	for _, p := range persisted {
		if p.JobID == jobID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no persisted listener with job id %d", jobID)
	}
	if _, err := runCmd("sqlite3", sliverDB, removeStaleListenerSQL(jobID)); err != nil {
		return err
	}
	return nil
}

// removeStaleListenerSQL builds the delete transaction. The protocol tables are
// cleared first (the subquery still resolves the listener_jobs UUID at that
// point); listener_jobs is deleted last. jobID is a uint32 so there is no
// injection surface. Deleting from every protocol table by the same
// listener_job_id is safe — at most one table has a matching row.
func removeStaleListenerSQL(jobID uint32) string {
	sub := fmt.Sprintf("(SELECT id FROM listener_jobs WHERE job_id=%d)", jobID)
	return strings.Join([]string{
		"PRAGMA busy_timeout=5000;",
		"BEGIN IMMEDIATE;",
		"DELETE FROM http_listeners WHERE listener_job_id IN " + sub + ";",
		"DELETE FROM mtls_listeners WHERE listener_job_id IN " + sub + ";",
		"DELETE FROM dns_listeners WHERE listener_job_id IN " + sub + ";",
		"DELETE FROM wg_listeners WHERE listener_job_id IN " + sub + ";",
		"DELETE FROM multiplayer_listeners WHERE listener_job_id IN " + sub + ";",
		fmt.Sprintf("DELETE FROM listener_jobs WHERE job_id=%d;", jobID),
		"COMMIT;",
	}, "\n")
}
