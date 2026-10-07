package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/health"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/proactivejournal"
	"time"
)

const journalAISchema = `CREATE TABLE IF NOT EXISTS journal_ai_settings(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL CHECK(length(body)<=16384 AND json_valid(body)));
CREATE TABLE IF NOT EXISTS journal_ai_mutations(id INTEGER PRIMARY KEY CHECK(id=1),revision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS journal_ai_attempts(device TEXT NOT NULL,incident TEXT NOT NULL,revision TEXT NOT NULL,unit TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL DEFAULT 0,model_started INTEGER NOT NULL DEFAULT 0,capture BLOB,PRIMARY KEY(device,incident));`

var ErrJournalAI = errors.New("journal_ai_state_unavailable")
var ErrJournalAIConflict = errors.New("journal_ai_state_changed")
var ErrJournalAIScope = errors.New("journal_ai_scope_invalid")
var ErrJournalAIFenced = errors.New("journal_ai_mutation_unresolved")
var ErrJournalAIFenceUnconfirmed = errors.New("journal_ai_durable_stop_unconfirmed")

// JournalAIReceipt is explicit future-capture AND model-export approval. It is
// separate from local helper consent and contains no keys or journal messages.
type JournalAIReceipt struct {
	Revision              string                    `json:"revision"`
	Enabled               bool                      `json:"enabled"`
	ManagerID             string                    `json:"managerId"`
	Transport             string                    `json:"transport"`
	ProviderRevision      string                    `json:"providerRevision"`
	CredentialGeneration  string                    `json:"credentialGeneration"`
	BaseURL               string                    `json:"baseURL"`
	Model                 string                    `json:"model"`
	Targets               []proactivejournal.Target `json:"targets"`
	LookbackMinutes       int                       `json:"lookbackMinutes"`
	DataScope             string                    `json:"dataScope"`
	CaptureAcknowledged   bool                      `json:"captureAcknowledged"`
	ExportAcknowledged    bool                      `json:"exportAcknowledged"`
	PlaintextAcknowledged bool                      `json:"plaintextAcknowledged"`
	ApprovedBy            string                    `json:"approvedBy"`
	ApprovedAt            time.Time                 `json:"approvedAt"`
	Binding               string                    `json:"binding"`
}

func JournalAIRevision() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return "cfg-" + hex.EncodeToString(b[:]), nil
}
func (r JournalAIReceipt) binding() string {
	r.Binding = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (r JournalAIReceipt) Valid() bool {
	if !enrollmentcrypto.ValidID(r.Revision, "cfg-") || r.Targets == nil || len(r.Targets) > proactivejournal.MaxTargets || r.DataScope != proactivejournal.DataScope || r.Binding != r.binding() {
		return false
	}
	if !r.Enabled {
		return len(r.Targets) == 0
	}
	if r.ManagerID == "" || len(r.ManagerID) > 80 || r.Transport != "tls" && r.Transport != "http-test" || !enrollmentcrypto.ValidID(r.ProviderRevision, "cfg-") || !enrollmentcrypto.ValidID(r.CredentialGeneration, "cfg-") || r.BaseURL == "" || len(r.BaseURL) > 512 || r.Model == "" || len(r.Model) > 128 || len(r.Targets) == 0 || r.LookbackMinutes != 5 && r.LookbackMinutes != 15 || !r.CaptureAcknowledged || !r.ExportAcknowledged || r.Transport == "http-test" && !r.PlaintextAcknowledged || r.ApprovedBy != "shared-administrator" || r.ApprovedAt.IsZero() {
		return false
	}
	seen := map[string]bool{}
	for _, t := range r.Targets {
		key := t.DeviceID + ":" + t.Unit
		if !enrollmentcrypto.ValidID(t.DeviceID, "agent_") || !proactivejournal.ValidUnit(t.Unit) || seen[key] || journalgeneration.Validate(t.Generation) != nil {
			return false
		}
		if _, err := health.Services([]string{t.Unit}); err != nil {
			return false
		}
		seen[key] = true
	}
	return true
}
func initJournalAI(tx *sql.Tx) error {
	// Preserve any unresolved mutation fence. It blocks only JournalAIReceipt;
	// ordinary health/inventory state remains usable after a manager restart.
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM journal_ai_settings`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		revision, err := JournalAIRevision()
		if err != nil {
			return err
		}
		r := JournalAIReceipt{Revision: revision, Targets: []proactivejournal.Target{}, DataScope: proactivejournal.DataScope}
		r.Binding = r.binding()
		raw, _ := json.Marshal(r)
		if _, err = tx.Exec(`INSERT INTO journal_ai_settings(id,body)VALUES(1,?)`, raw); err != nil {
			return err
		}
	}
	// Restart never resumes inference or adopts a live source request. Exact
	// known captures must still be suppressed, even after their scope changes.
	_, err := tx.Exec(`UPDATE journal_ai_attempts SET state=CASE WHEN capture IS NULL THEN 'capture_unconfirmed' ELSE 'cancel_pending' END WHERE state IN ('preparing','capturing','analyzing')`)
	return err
}
func decodeJournalAI(raw []byte) (JournalAIReceipt, error) {
	var r JournalAIReceipt
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16384 || d.Decode(&r) != nil || !r.Valid() {
		return r, ErrJournalAI
	}
	return r, nil
}
func (s *Store) JournalAIReceipt(ctx context.Context) (JournalAIReceipt, error) {
	var raw []byte
	var pending int
	if e := s.db.QueryRowContext(ctx, `SELECT body,(SELECT count(*) FROM journal_ai_mutations) FROM journal_ai_settings WHERE id=1`).Scan(&raw, &pending); e != nil {
		return JournalAIReceipt{}, e
	}
	if pending != 0 {
		return JournalAIReceipt{}, ErrJournalAIFenced
	}
	return decodeJournalAI(raw)
}

// stageJournalAIHealth is validation-only. Multiple selected units for the same
// device are accumulated before either the fence or health mutation is written.
func stageJournalAIHealth(ctx context.Context, tx *sql.Tx, r JournalAIReceipt) (map[string][]byte, error) {
	staged := map[string][]byte{}
	if !r.Enabled {
		return staged, nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM health_devices`).Scan(&count); err != nil {
		return nil, err
	}
	for _, target := range r.Targets {
		body, exists := staged[target.DeviceID]
		state := health.New()
		if !exists {
			err := tx.QueryRowContext(ctx, `SELECT body FROM health_devices WHERE id=?`, target.DeviceID).Scan(&body)
			if errors.Is(err, sql.ErrNoRows) {
				count++
				body = nil
			} else if err != nil {
				return nil, err
			}
			if count > 25 {
				return nil, ErrJournalAIScope
			}
		}
		if len(body) > 0 {
			var err error
			state, err = decodeHealth(body)
			if err != nil {
				return nil, err
			}
		}
		names := append([]string{}, state.MonitoredServices...)
		found := false
		for _, name := range names {
			found = found || name == target.Unit
		}
		if !found {
			names = append(names, target.Unit)
		}
		if state.SetServices(names, r.ApprovedAt) != nil {
			return nil, ErrJournalAIScope
		}
		if state.Validate() != nil {
			return nil, ErrJournalAI
		}
		body, err := json.Marshal(state)
		if err != nil || len(body) > health.MaxStateBytes {
			return nil, ErrJournalAI
		}
		staged[target.DeviceID] = body
	}
	return staged, nil
}

// SaveJournalAIReceipt validates before creating a durable mutation fence.
// Receipt, monitoring additions, cancellation obligations and fence removal then
// commit together. An interrupted/uncertain final commit cannot revive an older
// enabled scope after restart. No local collection permission is granted here.
func (s *Store) SaveJournalAIReceipt(ctx context.Context, expected string, r JournalAIReceipt) error {
	r.Binding = r.binding()
	if !r.Valid() {
		return ErrJournalAIScope
	}
	raw, _ := json.Marshal(r)
	if len(raw) > 16384 {
		return ErrJournalAIScope
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrJournalAIFenceUnconfirmed
	}
	defer tx.Rollback()
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_mutations`).Scan(&pending); err != nil {
		return ErrJournalAIFenceUnconfirmed
	}
	if pending != 0 {
		return ErrJournalAIFenced
	}
	var prior []byte
	if err = tx.QueryRowContext(ctx, `SELECT body FROM journal_ai_settings WHERE id=1`).Scan(&prior); err != nil {
		return ErrJournalAIFenceUnconfirmed
	}
	old, err := decodeJournalAI(prior)
	if err != nil {
		return err
	}
	if old.Revision != expected || old.Revision == r.Revision {
		return ErrJournalAIConflict
	}
	if _, err = stageJournalAIHealth(ctx, tx, r); err != nil {
		if errors.Is(err, ErrJournalAIScope) {
			return err
		}
		return ErrJournalAIFenceUnconfirmed
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO journal_ai_mutations(id,revision)VALUES(1,?)`, r.Revision); err != nil {
		return ErrJournalAIFenceUnconfirmed
	}
	if err = tx.Commit(); err != nil {
		return ErrJournalAIFenceUnconfirmed
	}

	commit, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrJournalAIFenced
	}
	defer commit.Rollback()
	var fence string
	if err = commit.QueryRowContext(ctx, `SELECT revision FROM journal_ai_mutations WHERE id=1`).Scan(&fence); err != nil || fence != r.Revision {
		return ErrJournalAIFenced
	}
	if err = commit.QueryRowContext(ctx, `SELECT body FROM journal_ai_settings WHERE id=1`).Scan(&prior); err != nil {
		return ErrJournalAIFenced
	}
	old, err = decodeJournalAI(prior)
	if err != nil || old.Revision != expected {
		return ErrJournalAIFenced
	}
	staged, err := stageJournalAIHealth(ctx, commit, r)
	if err != nil {
		return ErrJournalAIFenced
	}
	for device, body := range staged {
		if _, err = commit.ExecContext(ctx, `INSERT INTO health_devices(id,body)VALUES(?,?) ON CONFLICT(id)DO UPDATE SET body=excluded.body`, device, body); err != nil {
			return ErrJournalAIFenced
		}
	}
	if _, err = commit.ExecContext(ctx, `UPDATE journal_ai_settings SET body=? WHERE id=1`, raw); err != nil {
		return ErrJournalAIFenced
	}
	if _, err = commit.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='cancel_pending' WHERE capture IS NOT NULL AND state NOT IN ('canceled','expired')`); err != nil {
		return ErrJournalAIFenced
	}
	if _, err = commit.ExecContext(ctx, `DELETE FROM journal_ai_mutations WHERE id=1 AND revision=?`, r.Revision); err != nil {
		return ErrJournalAIFenced
	}
	if err = commit.Commit(); err != nil {
		return ErrJournalAIFenced
	}
	return nil
}

func (s *Store) QueueJournalAICancel(ctx context.Context, a JournalAIAttempt) (bool, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='cancel_pending' WHERE device=? AND incident=? AND revision=? AND capture IS NOT NULL AND state NOT IN ('canceled','expired')`, a.DeviceID, a.IncidentID, a.Revision)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func (s *Store) ConfirmJournalAICancel(ctx context.Context, a JournalAIAttempt) error {
	_, err := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='canceled' WHERE device=? AND incident=? AND revision=? AND state='cancel_pending'`, a.DeviceID, a.IncidentID, a.Revision)
	return err
}
func (s *Store) JournalAICancellationPending(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_attempts WHERE state IN ('cancel_pending','capture_unconfirmed')`).Scan(&n)
	return n > 0, err
}
func (s *Store) JournalAIUnconfirmedCapture(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_attempts WHERE state='capture_unconfirmed'`).Scan(&n)
	return n > 0, err
}

// RetainJournalAIFailedCapture preserves only the exact known request metadata.
// If its full write fails, try a content-free uncertainty marker; neither path
// authorizes adoption, replacement, replay or inference after restart.
func (s *Store) RetainJournalAIFailedCapture(ctx context.Context, a JournalAIAttempt, c proactivejournal.Capture) error {
	raw, err := json.Marshal(c)
	if err != nil || len(raw) > journalCaptureBytes {
		return ErrJournalAI
	}
	r, err := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='cancel_pending',capture=?,expires=? WHERE device=? AND incident=? AND revision=? AND state NOT IN ('completed','canceled','expired')`, raw, c.Description.ExpiresAt.UnixMilli(), a.DeviceID, a.IncidentID, a.Revision)
	if err == nil {
		var n int64
		n, err = r.RowsAffected()
		if err == nil && n == 1 {
			return nil
		}
		if err == nil {
			err = ErrJournalAIConflict
		}
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='capture_unconfirmed',expires=? WHERE device=? AND incident=? AND revision=? AND capture IS NULL AND state NOT IN ('completed','canceled','expired')`, c.Description.ExpiresAt.UnixMilli(), a.DeviceID, a.IncidentID, a.Revision)
	return err
}
func (s *Store) ConfirmJournalAIFailedCaptureCanceled(ctx context.Context, a JournalAIAttempt) error {
	_, err := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='canceled' WHERE device=? AND incident=? AND revision=? AND state NOT IN ('completed','expired')`, a.DeviceID, a.IncidentID, a.Revision)
	return err
}
func (s *Store) ExpireJournalAIUnconfirmed(ctx context.Context, now time.Time) error {
	// A zero expiry means no returned description was durably recorded; never
	// invent a new TTL or silently declare that uncertain capture suppressed.
	// The ledger stores milliseconds; wait beyond that millisecond instead of
	// declaring suppression up to a fraction of a millisecond before source TTL.
	_, err := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='expired' WHERE state='capture_unconfirmed' AND expires>0 AND expires<?`, now.UnixMilli())
	return err
}

type JournalAIAttempt struct {
	DeviceID   string                    `json:"deviceId"`
	IncidentID string                    `json:"incidentId"`
	Revision   string                    `json:"revision"`
	Unit       string                    `json:"unit"`
	State      string                    `json:"state"`
	CreatedAt  time.Time                 `json:"createdAt"`
	ExpiresAt  *time.Time                `json:"expiresAt"`
	Capture    *proactivejournal.Capture `json:"-"`
}

func (s *Store) ClaimJournalAI(ctx context.Context, device string, x health.Incident, revision string, now time.Time) (bool, error) {
	if x.Kind != "service" || x.ResolvedAt != nil || x.OpenedAt.After(now) || !enrollmentcrypto.ValidID(device, "agent_") || !enrollmentcrypto.ValidID(revision, "cfg-") {
		return false, ErrJournalAI
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `DELETE FROM journal_ai_attempts WHERE created<? AND state NOT IN ('preparing','capturing','analyzing','cancel_pending','capture_unconfirmed') AND NOT EXISTS(SELECT 1 FROM health_devices h,json_each(h.body,'$.incidents')j WHERE h.id=journal_ai_attempts.device AND json_extract(j.value,'$.id')=journal_ai_attempts.incident AND json_extract(j.value,'$.resolvedAt')IS NULL)`, now.Add(-health.Retention).UnixMilli()); e != nil {
		return false, e
	}
	var n int
	var last sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_attempts WHERE device=? AND incident=?`, device, x.ID).Scan(&n); e != nil || n > 0 {
		return false, e
	}
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_attempts`).Scan(&n); e != nil || n >= 250 {
		return false, e
	}
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM journal_ai_attempts WHERE created>?`, now.Add(-time.Hour).UnixMilli()).Scan(&n); e != nil || n >= proactivejournal.MaxAnalysesPerHour {
		return false, e
	}
	if e = tx.QueryRowContext(ctx, `SELECT max(created) FROM journal_ai_attempts WHERE device=? AND unit=?`, device, x.Target).Scan(&last); e != nil {
		return false, e
	}
	if last.Valid && now.UnixMilli() < last.Int64+proactivejournal.Cooldown.Milliseconds() {
		return false, nil
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO journal_ai_attempts(device,incident,revision,unit,state,created)VALUES(?,?,?,?,'preparing',?)`, device, x.ID, revision, x.Target, now.UnixMilli()); e != nil {
		return false, e
	}
	return true, tx.Commit()
}
func (s *Store) JournalAIAttempts(ctx context.Context) ([]JournalAIAttempt, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT device,incident,revision,unit,state,created,expires,capture FROM journal_ai_attempts ORDER BY created DESC LIMIT 251`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []JournalAIAttempt{}
	for rows.Next() {
		var a JournalAIAttempt
		var created, expires int64
		var raw []byte
		if e = rows.Scan(&a.DeviceID, &a.IncidentID, &a.Revision, &a.Unit, &a.State, &created, &expires, &raw); e != nil {
			return nil, e
		}
		a.CreatedAt = time.UnixMilli(created).UTC()
		if expires != 0 {
			at := time.UnixMilli(expires).UTC()
			a.ExpiresAt = &at
		}
		if len(raw) > 0 {
			if len(raw) > journalCaptureBytes {
				return nil, ErrJournalAI
			}
			var c proactivejournal.Capture
			if json.Unmarshal(raw, &c) != nil {
				return nil, ErrJournalAI
			}
			a.Capture = &c
		}
		out = append(out, a)
	}
	if len(out) > 250 {
		return nil, ErrJournalAI
	}
	return out, rows.Err()
}

const journalCaptureBytes = 8192

func (s *Store) SetJournalAICapture(ctx context.Context, a JournalAIAttempt, c proactivejournal.Capture) error {
	raw, e := json.Marshal(c)
	if e != nil || len(raw) > journalCaptureBytes {
		return ErrJournalAI
	}
	r, e := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='capturing',capture=?,expires=? WHERE device=? AND incident=? AND revision=? AND state='preparing'`, raw, c.Description.ExpiresAt.UnixMilli(), a.DeviceID, a.IncidentID, a.Revision)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e != nil || n != 1 {
		return ErrJournalAIConflict
	}
	return nil
}
func (s *Store) FinishJournalAI(ctx context.Context, a JournalAIAttempt, state string) error {
	switch state {
	case "completed", "canceled", "expired", "unavailable", "invalid_response", "timeout", "interrupted", "busy":
	default:
		return ErrJournalAI
	}
	_, e := s.db.ExecContext(ctx, `UPDATE journal_ai_attempts SET state=? WHERE device=? AND incident=? AND revision=? AND state IN ('preparing','capturing','analyzing')`, state, a.DeviceID, a.IncidentID, a.Revision)
	return e
}

// A second durable admission is at actual model-send time, so delayed captures
// cannot bunch into an unbounded burst across the rolling-hour boundary.
func (s *Store) StartJournalAIModel(ctx context.Context, a JournalAIAttempt, now time.Time) (bool, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var n int
	var last sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT count(*),max(model_started) FROM journal_ai_attempts WHERE model_started>?`, now.Add(-time.Hour).UnixMilli()).Scan(&n, &last); e != nil {
		return false, e
	}
	if n >= proactivejournal.MaxAnalysesPerHour || last.Valid && now.UnixMilli() < last.Int64+time.Minute.Milliseconds() {
		return false, nil
	}
	var total int
	var globalLast sql.NullInt64
	if e = tx.QueryRowContext(ctx, `SELECT count(*),max(at) FROM (SELECT created AS at FROM health_analyses UNION ALL SELECT model_started AS at FROM journal_ai_attempts WHERE model_started>0) WHERE at>?`, now.Add(-time.Hour).UnixMilli()).Scan(&total, &globalLast); e != nil {
		return false, e
	}
	if total >= HealthAnalysisHourlyLimit || globalLast.Valid && now.UnixMilli() < globalLast.Int64+HealthAnalysisInterval.Milliseconds() {
		return false, nil
	}
	r, e := tx.ExecContext(ctx, `UPDATE journal_ai_attempts SET state='analyzing',model_started=? WHERE device=? AND incident=? AND revision=? AND state='capturing'`, now.UnixMilli(), a.DeviceID, a.IncidentID, a.Revision)
	if e != nil {
		return false, e
	}
	n64, e := r.RowsAffected()
	if e != nil || n64 != 1 {
		return false, e
	}
	return true, tx.Commit()
}
