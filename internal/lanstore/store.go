// Package lanstore persists one environment's public agent approvals and bounded
// latest observations. It stores no private keys, passwords or browser sessions.
package lanstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var ErrReplay = errors.New("telemetry sequence or timestamp is not newer")
var ErrStorage = errors.New("LAN state storage is unavailable")
var ErrBinding = errors.New("agent identity or revocation binding cannot change")

type Store struct{ db *sql.DB }

func safePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", ErrStorage
	}
	current := absolute
	for {
		if info, err := os.Lstat(current); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", ErrStorage
			}
		} else if !os.IsNotExist(err) {
			return "", ErrStorage
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return absolute, nil
}

// Open is Linux-only until Windows ACL and macOS server lifecycle are reviewed.
// Existing insecure files are rejected rather than silently changing permissions.
func Open(path string) (*Store, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("LAN manager storage is currently supported on Linux only")
	}
	absolute, err := safePath(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, ErrStorage
	}
	if err = privateStateDirectory(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err = privateStateFile(absolute + suffix); err != nil {
			return nil, err
		}
	}
	if info, err := os.Lstat(absolute); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, ErrStorage
		}
	} else if os.IsNotExist(err) {
		file, e := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if e != nil {
			return nil, ErrStorage
		}
		file.Close()
	} else {
		return nil, ErrStorage
	}
	u := url.URL{Scheme: "file", Path: absolute}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrStorage
	}
	db.SetMaxOpenConns(1)
	fail := func() (*Store, error) { db.Close(); return nil, ErrStorage }
	for _, query := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err = db.Exec(query); err != nil {
			return fail()
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return fail()
	}
	defer tx.Rollback()
	for _, query := range []string{`CREATE TABLE IF NOT EXISTS lan_agents(id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, body TEXT NOT NULL CHECK(json_valid(body)))`, `CREATE TABLE IF NOT EXISTS lan_samples(agent_id TEXT PRIMARY KEY REFERENCES lan_agents(id), sequence INTEGER NOT NULL, generated_at TEXT NOT NULL, collected_at TEXT NOT NULL, received_at TEXT NOT NULL, payload_hash TEXT NOT NULL, body TEXT NOT NULL CHECK(json_valid(body)))`} {
		if _, err = tx.Exec(query); err != nil {
			_ = tx.Rollback()
			return fail()
		}
	}
	if err = tx.Commit(); err != nil {
		return fail()
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Load(ctx context.Context) ([]lantrust.Agent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,fingerprint,body FROM lan_agents ORDER BY id")
	if err != nil {
		return nil, ErrStorage
	}
	defer rows.Close()
	agents := []lantrust.Agent{}
	for rows.Next() {
		var raw, id, fingerprint string
		var agent lantrust.Agent
		if err = rows.Scan(&id, &fingerprint, &raw); err != nil {
			return nil, ErrStorage
		}
		if err = json.Unmarshal([]byte(raw), &agent); err != nil || agent.ID != id || agent.FingerprintSHA256 != fingerprint {
			return nil, ErrStorage
		}
		agents = append(agents, agent)
		if len(agents) > lantrust.MaxAgents {
			return nil, ErrStorage
		}
	}
	if rows.Err() != nil {
		return nil, ErrStorage
	}
	return agents, nil
}
func (s *Store) Save(ctx context.Context, agent lantrust.Agent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStorage
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRowContext(ctx, "SELECT body FROM lan_agents WHERE id=?", agent.ID).Scan(&raw)
	if err == nil {
		var old lantrust.Agent
		if json.Unmarshal([]byte(raw), &old) != nil {
			return ErrStorage
		}
		if old.ID != agent.ID || old.FingerprintSHA256 != agent.FingerprintSHA256 || !old.ApprovedAt.Equal(agent.ApprovedAt) || !old.NotBefore.Equal(agent.NotBefore) || !old.ExpiresAt.Equal(agent.ExpiresAt) || (!old.RevokedAt.IsZero() && !old.RevokedAt.Equal(agent.RevokedAt)) {
			return ErrBinding
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return ErrStorage
	}
	encoded, err := json.Marshal(agent)
	if err != nil {
		return ErrStorage
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO lan_agents(id,fingerprint,body) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", agent.ID, agent.FingerprintSHA256, string(encoded)); err != nil {
		return ErrBinding
	}
	if err = tx.Commit(); err != nil {
		return ErrStorage
	}
	return nil
}

type Receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	AgentID       string    `json:"agentId"`
	Sequence      uint64    `json:"sequence"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	Duplicate     bool      `json:"duplicate"`
}

func (s *Store) SaveObservation(ctx context.Context, agent lantrust.Agent, sequence uint64, generatedAt time.Time, device model.Device, raw []byte, receivedAt time.Time) (Receipt, error) {
	receipt := Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: agent.ID, Sequence: sequence, CollectedAt: device.LastSeen, ReceivedAt: receivedAt.UTC()}
	if sequence == 0 || sequence > 1<<63-1 {
		return receipt, ErrReplay
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, ErrStorage
	}
	defer tx.Rollback()
	var agentBody string
	if tx.QueryRowContext(ctx, "SELECT body FROM lan_agents WHERE id=? AND fingerprint=?", agent.ID, agent.FingerprintSHA256).Scan(&agentBody) != nil {
		return receipt, ErrBinding
	}
	var current lantrust.Agent
	if json.Unmarshal([]byte(agentBody), &current) != nil || !current.RevokedAt.IsZero() || !receivedAt.Before(current.ExpiresAt) {
		return receipt, ErrBinding
	}
	var oldSequence uint64
	var oldGenerated, oldCollected, oldReceived, oldDigest string
	err = tx.QueryRowContext(ctx, "SELECT sequence,generated_at,collected_at,received_at,payload_hash FROM lan_samples WHERE agent_id=?", agent.ID).Scan(&oldSequence, &oldGenerated, &oldCollected, &oldReceived, &oldDigest)
	if err == nil {
		generated, e1 := time.Parse(time.RFC3339Nano, oldGenerated)
		collected, e2 := time.Parse(time.RFC3339Nano, oldCollected)
		received, e3 := time.Parse(time.RFC3339Nano, oldReceived)
		if e1 != nil || e2 != nil || e3 != nil {
			return receipt, ErrStorage
		}
		if sequence == oldSequence && digest == oldDigest {
			receipt.CollectedAt = collected
			receipt.ReceivedAt = received
			receipt.Duplicate = true
			return receipt, nil
		}
		if sequence <= oldSequence || !generatedAt.After(generated) || !device.LastSeen.After(collected) {
			return receipt, ErrReplay
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return receipt, ErrStorage
	}
	device.ID = agent.ID
	device.Name = agent.Label
	device.Site = "Local network"
	device.Group = "Managed devices"
	device.Source = "lan"
	device.IP = nil
	device.Synthetic = false
	device.Status = "unknown"
	device.Tags = []string{"lan", "read-only", "manual-certificate-approval"}
	encoded, err := json.Marshal(device)
	if err != nil {
		return receipt, ErrStorage
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lan_samples(agent_id,sequence,generated_at,collected_at,received_at,payload_hash,body) VALUES(?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET sequence=excluded.sequence,generated_at=excluded.generated_at,collected_at=excluded.collected_at,received_at=excluded.received_at,payload_hash=excluded.payload_hash,body=excluded.body`, agent.ID, sequence, generatedAt.UTC().Format(time.RFC3339Nano), device.LastSeen.UTC().Format(time.RFC3339Nano), receivedAt.UTC().Format(time.RFC3339Nano), digest, string(encoded))
	if err != nil {
		return receipt, ErrStorage
	}
	if err = tx.Commit(); err != nil {
		return receipt, ErrStorage
	}
	return receipt, nil
}
func (s *Store) Devices(ctx context.Context, agents []lantrust.Agent, now time.Time) ([]model.Device, error) {
	result := []model.Device{}
	for _, agent := range agents {
		metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Awaiting authenticated agent observation"}
		d := model.Device{ID: agent.ID, Name: agent.Label, Platform: "unknown", OS: "Awaiting agent", Site: "Local network", Group: "Managed devices", Source: "lan", Status: "unknown", AgentVersion: "unknown", CPU: metric, Memory: metric, Disk: metric, Uptime: "Unknown", Tags: []string{"lan", "read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
		var raw, receivedText string
		err := s.db.QueryRowContext(ctx, "SELECT body,received_at FROM lan_samples WHERE agent_id=?", agent.ID).Scan(&raw, &receivedText)
		if err == nil {
			if json.Unmarshal([]byte(raw), &d) != nil {
				return nil, ErrStorage
			}
			received, err := time.Parse(time.RFC3339Nano, receivedText)
			if err != nil {
				return nil, ErrStorage
			}
			old := now.Sub(received) > 2*time.Minute || now.Sub(d.LastSeen) > 2*time.Minute
			for _, m := range []model.Metric{d.CPU, d.Memory, d.Disk} {
				old = old || now.Sub(m.CollectedAt) > 2*time.Minute
			}
			for _, e := range d.Evidence {
				old = old || now.Sub(e.CollectedAt) > 2*time.Minute
			}
			if old {
				for _, m := range []*model.Metric{&d.CPU, &d.Memory, &d.Disk} {
					if m.Quality == "healthy" {
						m.Quality = "stale"
					}
				}
				for i := range d.Evidence {
					if d.Evidence[i].Quality == "healthy" {
						d.Evidence[i].Quality = "stale"
					}
				}
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, ErrStorage
		}
		// Registry expiry comes from the approved leaf certificate, never telemetry.
		d.AgentCertificate = &model.AgentCertificate{Source: "manual-approval", CheckedAt: now.UTC()}
		if !agent.ExpiresAt.IsZero() {
			expires := agent.ExpiresAt.UTC()
			d.AgentCertificate.ExpiresAt = &expires
		}
		trust := "supported"
		detail := "Manually approved certificate; identity is assigned by this manager. This does not establish overall device health."
		if !agent.RevokedAt.IsZero() || !now.Before(agent.ExpiresAt) {
			trust = "denied"
			detail = "Agent certificate approval is revoked or expired; further telemetry is rejected."
		}
		d.Capabilities = append(d.Capabilities, model.Capability{ID: "agent_identity", Name: "Agent certificate identity", Status: trust, Detail: detail})
		result = append(result, d)
	}
	return result, nil
}
