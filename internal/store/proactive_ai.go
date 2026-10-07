package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/analysis"
	"localrmm/internal/health"
	"math"
	"strings"
	"time"
)

const (
	MaxHealthAnalyses         = 250
	MaxHealthAnalysisBytes    = 32 << 10
	HealthAnalysisHourlyLimit = 6
	HealthAnalysisInterval    = time.Minute
	HealthAnalysisCooldown    = 30 * time.Minute
	HealthAnalysisRetention   = 30 * 24 * time.Hour
	// Leave room for timestamps and status, including a future recovery marker.
	maxHealthAnalysisResultBytes = MaxHealthAnalysisBytes - 1024
)

var (
	ErrInvalidHealthAnalysis  = errors.New("invalid health analysis")
	ErrHealthAnalysisConflict = errors.New("health analysis claim is not active")
)

// This table is a consume-once attempt ledger, not provider authorization.
// Revision only binds completion to its claim; it is never returned publicly.
const proactiveAISchema = `CREATE TABLE IF NOT EXISTS health_analyses (
 device TEXT NOT NULL CHECK(length(device)>0 AND length(device)<=128),
 incident TEXT NOT NULL CHECK(length(incident)>0 AND length(incident)<=128),
 rule TEXT NOT NULL CHECK(length(rule)>0 AND length(rule)<=136),
 revision TEXT NOT NULL CHECK(length(revision)>0 AND length(revision)<=128),
 status TEXT NOT NULL CHECK(status IN ('running','completed','timeout','unavailable','invalid_response','canceled','not_configured','busy','interrupted')),
 created INTEGER NOT NULL,
 finished INTEGER,
 recovered INTEGER,
 result BLOB CHECK(result IS NULL OR (length(result)>0 AND length(result)<=31744 AND json_valid(result))),
 PRIMARY KEY(device,incident)
);
CREATE INDEX IF NOT EXISTS health_analysis_created ON health_analyses(created);
CREATE INDEX IF NOT EXISTS health_analysis_rule ON health_analyses(device,rule,created);`

// HealthAnalysis is local operator-only information. AI failures retain their
// own status and never acquire fabricated model findings.
type HealthAnalysis struct {
	Status      string           `json:"status"`
	CreatedAt   time.Time        `json:"createdAt"`
	FinishedAt  *time.Time       `json:"finishedAt"`
	RecoveredAt *time.Time       `json:"recoveredAt"`
	Result      *analysis.Result `json:"result"`
}

// HealthAnalysisClaim contains the exact current health snapshot admitted by
// the transaction. A caller must not replace it with subsequently read evidence.
type HealthAnalysisClaim struct {
	Incident health.Incident
	Check    health.Check
}

// ClaimHealthAnalysis commits the claim before any provider work. Nil means no
// attempt is permitted. Deduplication is independent of provider/config revision.
// The caller separately owns explicit provider/device-scoped approval, whether
// session-only or restored from validated protected settings.
func (s *Store) ClaimHealthAnalysis(ctx context.Context, deviceID, incidentID, revision string, enabledAt, now time.Time) (*HealthAnalysisClaim, error) {
	if !healthAnalysisToken(deviceID) || !healthAnalysisToken(incidentID) || !healthAnalysisToken(revision) || !healthAnalysisTime(now) || !healthAnalysisTime(enabledAt) || enabledAt.After(now) {
		return nil, ErrInvalidHealthAnalysis
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM health_devices WHERE id=?`, deviceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	state, err := decodeHealth(raw)
	if err != nil {
		return nil, err
	}
	view := state.View(deviceID, now)
	if view.Status == "maintenance" {
		return nil, nil
	}
	var claim *HealthAnalysisClaim
	for _, incident := range state.Incidents {
		if incident.ID != incidentID || incident.ResolvedAt != nil || incident.OpenedAt.Before(enabledAt) || incident.OpenedAt.After(now) || incident.LastObservedAt.After(now) {
			continue
		}
		for i, check := range view.Checks {
			if check.Key == incident.Key && check.Kind == incident.Kind && check.Target == incident.Target && check.State == "open" && validHealthAnalysisCheck(check, now) {
				claim = &HealthAnalysisClaim{Incident: incident, Check: state.Checks[i]}
				break
			}
		}
	}
	if claim == nil {
		return nil, nil
	}
	if err = pruneHealthAnalyses(ctx, tx, now); err != nil {
		return nil, err
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM health_analyses WHERE device=? AND incident=?`, deviceID, incidentID).Scan(&existing); err != nil {
		return nil, err
	}
	if existing != 0 {
		return nil, tx.Commit()
	}
	var recent int
	var last, ruleLast sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),max(created) FROM health_analyses WHERE created>?`, now.Add(-time.Hour).UnixMilli()).Scan(&recent, &last); err != nil {
		return nil, err
	}
	if recent >= HealthAnalysisHourlyLimit || last.Valid && now.UnixMilli() < last.Int64+HealthAnalysisInterval.Milliseconds() {
		return nil, tx.Commit()
	}
	if err = tx.QueryRowContext(ctx, `SELECT max(created) FROM health_analyses WHERE device=? AND rule=?`, deviceID, claim.Incident.Key).Scan(&ruleLast); err != nil {
		return nil, err
	}
	if ruleLast.Valid && now.UnixMilli() < ruleLast.Int64+HealthAnalysisCooldown.Milliseconds() {
		return nil, tx.Commit()
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM health_analyses`).Scan(&count); err != nil {
		return nil, err
	}
	if count >= MaxHealthAnalyses {
		// Evict only terminal, closed incidents outside the complete rate window.
		// If all space is protected, skip AI without blocking deterministic health.
		if _, err = tx.ExecContext(ctx, `DELETE FROM health_analyses WHERE (device,incident) IN (
 SELECT a.device,a.incident FROM health_analyses a WHERE a.status<>'running' AND a.created<=?
 AND NOT EXISTS (SELECT 1 FROM health_devices h,json_each(h.body,'$.incidents') j WHERE h.id=a.device AND json_extract(j.value,'$.id')=a.incident AND json_extract(j.value,'$.resolvedAt') IS NULL)
 ORDER BY a.created,a.device,a.incident LIMIT ?
)`, now.Add(-time.Hour).UnixMilli(), count-MaxHealthAnalyses+1); err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM health_analyses`).Scan(&count); err != nil {
			return nil, err
		}
		if count >= MaxHealthAnalyses {
			return nil, tx.Commit()
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO health_analyses(device,incident,rule,revision,status,created) VALUES(?,?,?,?,'running',?)`, deviceID, incidentID, claim.Incident.Key, revision, now.UnixMilli()); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return claim, nil
}

// CompleteHealthAnalysis never retries a finished claim or changes its revision.
// Provider failures are ordinary explicit result statuses, not successful AI.
func (s *Store) CompleteHealthAnalysis(ctx context.Context, deviceID, incidentID, revision string, result analysis.Result, now time.Time) error {
	if !healthAnalysisArgs(deviceID, incidentID, revision, now) {
		return ErrInvalidHealthAnalysis
	}
	raw, err := encodeHealthAnalysisResult(result)
	if err != nil {
		return err
	}
	if result.Packet.Case.ID != incidentID {
		return ErrInvalidHealthAnalysis
	}
	return s.finishHealthAnalysis(ctx, deviceID, incidentID, revision, result.AI.Status, raw, now)
}

// FinishHealthAnalysisFailure consumes the claim without retaining evidence,
// including cancellation when the operator revokes approval during inference.
func (s *Store) FinishHealthAnalysisFailure(ctx context.Context, deviceID, incidentID, revision, status string, now time.Time) error {
	if !healthAnalysisArgs(deviceID, incidentID, revision, now) || status != "canceled" && status != "unavailable" && status != "interrupted" {
		return ErrInvalidHealthAnalysis
	}
	return s.finishHealthAnalysis(ctx, deviceID, incidentID, revision, status, nil, now)
}

func (s *Store) finishHealthAnalysis(ctx context.Context, deviceID, incidentID, revision, status string, raw []byte, now time.Time) error {
	// A retained packet must also identify the kind of the claimed rule.
	var kind string
	if raw != nil {
		var result analysis.Result
		if json.Unmarshal(raw, &result) != nil {
			return ErrInvalidHealthAnalysis
		}
		kind = result.Packet.Case.Category
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE health_analyses SET status=?,finished=?,result=CASE WHEN created>=? THEN ? ELSE NULL END WHERE device=? AND incident=? AND revision=? AND status='running' AND created<=? AND (?='' OR substr(rule,1,instr(rule,':')-1)=?)`, status, now.UnixMilli(), now.Add(-HealthAnalysisRetention).UnixMilli(), raw, deviceID, incidentID, revision, now.UnixMilli(), kind, kind)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrHealthAnalysisConflict
	}
	if err = pruneHealthAnalyses(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

// HealthAnalyses returns bounded recent records only. Durable old open claims
// remain private to deduplication even after their evidence retention expires.
func (s *Store) HealthAnalyses(ctx context.Context, deviceID string) (map[string]HealthAnalysis, error) {
	if !healthAnalysisToken(deviceID) {
		return nil, ErrInvalidHealthAnalysis
	}
	rows, err := s.db.QueryContext(ctx, `SELECT incident,rule,status,created,finished,recovered,result FROM health_analyses WHERE device=? AND created>=? ORDER BY created DESC,incident LIMIT ?`, deviceID, time.Now().UTC().Add(-HealthAnalysisRetention).UnixMilli(), MaxHealthAnalyses+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]HealthAnalysis{}
	for rows.Next() {
		var id, rule string
		var value HealthAnalysis
		var created int64
		var finished, recovered sql.NullInt64
		var raw []byte
		if err = rows.Scan(&id, &rule, &value.Status, &created, &finished, &recovered, &raw); err != nil {
			return nil, err
		}
		value.CreatedAt = time.UnixMilli(created).UTC()
		if finished.Valid {
			t := time.UnixMilli(finished.Int64).UTC()
			value.FinishedAt = &t
		}
		if recovered.Valid {
			t := time.UnixMilli(recovered.Int64).UTC()
			value.RecoveredAt = &t
		}
		if !validHealthAnalysisRecord(id, value, raw != nil) {
			return nil, ErrInvalidHealthAnalysis
		}
		if raw != nil {
			var result analysis.Result
			if len(raw) > maxHealthAnalysisResultBytes || json.Unmarshal(raw, &result) != nil {
				return nil, ErrInvalidHealthAnalysis
			}
			if _, err = encodeHealthAnalysisResult(result); err != nil || value.Status != result.AI.Status || result.Packet.Case.ID != id || result.Packet.Case.Category != strings.SplitN(rule, ":", 2)[0] {
				return nil, ErrInvalidHealthAnalysis
			}
			value.Result = &result
		}
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > MaxHealthAnalysisBytes {
			return nil, ErrInvalidHealthAnalysis
		}
		out[id] = value
		if len(out) > MaxHealthAnalyses {
			return nil, ErrInvalidHealthAnalysis
		}
	}
	return out, rows.Err()
}

// Actual recoveries are recorded atomically with health, including transitions
// that were immediately pruned from bounded history. Stopping monitoring is not
// recovery. This does not modify model output or add it to the alarm outbox.
func recoverHealthAnalyses(ctx context.Context, tx *sql.Tx, deviceID string, state health.State, transitions []health.Incident) error {
	incidents := append(append([]health.Incident{}, state.Incidents...), transitions...)
	for _, incident := range incidents {
		if incident.ClosedReason != "recovered" || incident.ResolvedAt == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE health_analyses SET recovered=? WHERE device=? AND incident=? AND recovered IS NULL`, incident.ResolvedAt.UnixMilli(), deviceID, incident.ID); err != nil {
			return err
		}
	}
	return nil
}

// PruneHealthAnalyses expires local evidence independently of provider approval.
// The bounded ledger contains at most MaxHealthAnalyses records. Current open
// consume-once markers survive; no provider, settings, or alarm work is performed.
// Call from the monitor even while proactive analysis is disabled, never from GET.
func (s *Store) PruneHealthAnalyses(ctx context.Context, now time.Time) error {
	if !healthAnalysisTime(now) {
		return ErrInvalidHealthAnalysis
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = pruneHealthAnalyses(ctx, tx, now); err != nil {
		return err
	}
	return tx.Commit()
}

func pruneHealthAnalyses(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-HealthAnalysisRetention).UnixMilli()
	// Evidence expires even while an old open claim must remain consumed.
	if _, err := tx.ExecContext(ctx, `UPDATE health_analyses SET result=NULL WHERE created<? AND result IS NOT NULL`, cutoff); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM health_analyses WHERE created<? AND status<>'running' AND NOT EXISTS (SELECT 1 FROM health_devices h,json_each(h.body,'$.incidents') j WHERE h.id=health_analyses.device AND json_extract(j.value,'$.id')=health_analyses.incident AND json_extract(j.value,'$.resolvedAt') IS NULL)`, cutoff)
	return err
}

func validHealthAnalysisRecord(id string, record HealthAnalysis, hasResult bool) bool {
	if !healthAnalysisToken(id) || !healthAnalysisTime(record.CreatedAt) {
		return false
	}
	if record.FinishedAt != nil && (!healthAnalysisTime(*record.FinishedAt) || record.FinishedAt.Before(record.CreatedAt)) {
		return false
	}
	if record.RecoveredAt != nil && (!healthAnalysisTime(*record.RecoveredAt) || record.RecoveredAt.Before(record.CreatedAt)) {
		return false
	}
	switch record.Status {
	case "running":
		return record.FinishedAt == nil && !hasResult
	case "completed", "timeout", "invalid_response", "not_configured", "busy":
		return record.FinishedAt != nil && hasResult
	case "unavailable", "canceled":
		return record.FinishedAt != nil
	case "interrupted":
		return record.FinishedAt != nil && !hasResult
	}
	return false
}

func validHealthAnalysisCheck(check health.Check, now time.Time) bool {
	if check.ObservedAt == nil || !healthAnalysisTime(*check.ObservedAt) || check.ObservedAt.After(now) {
		return false
	}
	if check.Kind == "filesystem" {
		return check.Value != nil && !math.IsNaN(*check.Value) && !math.IsInf(*check.Value, 0) && *check.Value >= 0 && *check.Value <= 100
	}
	return (check.Kind == "offline" || check.Kind == "service") && check.Value == nil
}

func healthAnalysisArgs(deviceID, incidentID, revision string, now time.Time) bool {
	return healthAnalysisToken(deviceID) && healthAnalysisToken(incidentID) && healthAnalysisToken(revision) && healthAnalysisTime(now)
}
func healthAnalysisToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ':' || c == '.') {
			return false
		}
	}
	return true
}
func healthAnalysisTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1970 && value.Year() <= 9999
}
func healthAnalysisHash(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func encodeHealthAnalysisResult(result analysis.Result) ([]byte, error) {
	if result.SchemaVersion != analysis.ResultVersion || result.Packet.SchemaVersion != analysis.PacketVersion || result.Packet.DataScope != analysis.HealthDataScope || !healthAnalysisToken(result.ID) || !healthAnalysisHash(result.Fingerprint) || !healthAnalysisTime(result.GeneratedAt) || result.RootCauseConfirmed {
		return nil, ErrInvalidHealthAnalysis
	}
	if !healthAnalysisToken(result.Packet.Case.ID) || !strings.HasPrefix(result.Packet.Case.ID, "health_") || result.Packet.Case.RuleID != "health:"+result.Packet.Case.Category || result.Packet.Case.Category != "filesystem" && result.Packet.Case.Category != "service" && result.Packet.Case.Category != "offline" || len(result.Packet.Evidence) != 2 || len(result.Packet.MissingEvidenceIDs) != 0 {
		return nil, ErrInvalidHealthAnalysis
	}
	seen := map[string]bool{}
	for _, evidence := range result.Packet.Evidence {
		if seen[evidence.ID] || evidence.ID != "health-event" && evidence.ID != "health-snapshot" {
			return nil, ErrInvalidHealthAnalysis
		}
		seen[evidence.ID] = true
	}
	switch result.AI.Status {
	case "completed":
		if result.AI.Findings == nil {
			return nil, ErrInvalidHealthAnalysis
		}
		raw, err := json.Marshal(result.AI.Findings)
		if err != nil {
			return nil, ErrInvalidHealthAnalysis
		}
		if _, err := analysis.ValidateFindings(raw, result.Packet); err != nil {
			return nil, ErrInvalidHealthAnalysis
		}
	case "timeout", "unavailable", "invalid_response", "canceled", "not_configured", "busy":
		if result.AI.Findings != nil || len(result.AI.NextSteps) != 0 {
			return nil, ErrInvalidHealthAnalysis
		}
	default:
		return nil, ErrInvalidHealthAnalysis
	}
	raw, err := json.Marshal(result)
	if err != nil || len(raw) > maxHealthAnalysisResultBytes {
		return nil, ErrInvalidHealthAnalysis
	}
	return raw, nil
}
