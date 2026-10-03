package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/bundle"
	"localrmm/internal/collector"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"localrmm/internal/signedhttp"
	"net/http"
	"time"
)

type frame struct {
	SchemaVersion string        `json:"schemaVersion"`
	Sequence      uint64        `json:"sequence"`
	Observation   bundle.Bundle `json:"observation"`
}
type receipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	AgentID       string    `json:"agentId"`
	Sequence      uint64    `json:"sequence"`
	CollectedAt   time.Time `json:"collectedAt"`
	ReceivedAt    time.Time `json:"receivedAt"`
	Duplicate     bool      `json:"duplicate"`
}
type Report struct {
	SchemaVersion               string `json:"schemaVersion"`
	Status                      string `json:"status"`
	Profile                     string `json:"profile"`
	Sequence                    uint64 `json:"sequence,omitempty"`
	Duplicate                   bool   `json:"duplicate"`
	RetriedPending              bool   `json:"retriedPending"`
	DiscardedStale              bool   `json:"discardedStale"`
	AvailablePercentageFields   int    `json:"availablePercentageFields"`
	UnavailablePercentageFields int    `json:"unavailablePercentageFields"`
}

// Run performs at most one collection and one bounded delivery attempt. Pending
// exact bytes are durably retained after uncertain delivery. It never retries to
// another origin, alters old timestamps, creates credentials or installs a service.
func Run(ctx context.Context, m Material) (Report, error) {
	report := Report{SchemaVersion: "tracebolt.agent-run.v1", Status: "failed", Profile: m.config.Profile}
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if !m.valid() {
		return report, ErrConfiguration
	}
	report.Profile = m.config.Profile
	state, e := lanclientstate.Open(m.config.StateDirectory, m.binding)
	if e != nil {
		return report, ErrState
	}
	defer state.Close()
	pending, e := state.Pending()
	if e != nil {
		return report, ErrState
	}
	var f frame
	if pending != nil {
		f, e = decodeFrame(pending.Body(), pending.Sequence)
		if e != nil {
			return report, ErrState
		}
		if stale(f, time.Now().UTC()) {
			if state.Discard(pending.Digest) != nil {
				return report, ErrState
			}
			pending = nil
			report.DiscardedStale = true
		} else {
			report.RetriedPending = true
		}
	}
	if pending == nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		sequence, e := state.NextSequence()
		if e != nil {
			return report, ErrState
		}
		raw, e := bundle.Encode(collector.Snapshot())
		if e != nil {
			return report, ErrObservation
		}
		var observation bundle.Bundle
		if json.Unmarshal(raw, &observation) != nil {
			return report, ErrObservation
		}
		f = frame{SchemaVersion: FrameVersion, Sequence: sequence, Observation: observation}
		body, e := json.Marshal(f)
		if e != nil || len(body) > MaxFrameBytes {
			return report, ErrObservation
		}
		p, e := state.Stage(sequence, body)
		if e != nil {
			return report, ErrState
		}
		pending = &p
	}
	report.Sequence = pending.Sequence
	for _, v := range []bool{f.Observation.Observation.CPU.Value != nil && f.Observation.Observation.CPU.Quality == "healthy", f.Observation.Observation.Memory.Value != nil && f.Observation.Observation.Memory.Quality == "healthy", f.Observation.Observation.Disk.Value != nil && f.Observation.Observation.Disk.Quality == "healthy"} {
		if v {
			report.AvailablePercentageFields++
		} else {
			report.UnavailablePercentageFields++
		}
	}
	report.Status = "pending_retained"
	var req *http.Request
	if m.config.Profile == "http-test" {
		req, e = signedhttp.NewSignedRequest(ctx, m.config.ManagerOrigin, m.certificate, pending.Sequence, f.Observation.GeneratedAt, pending.Body())
	} else {
		req, e = http.NewRequestWithContext(ctx, "POST", m.config.ManagerOrigin+signedhttp.Path, bytes.NewReader(pending.Body()))
		if e == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if e != nil {
		return report, ErrConfiguration
	}
	client := newHTTPClient(m.tlsConfig, m.config.Profile == "http-test")
	defer client.CloseIdleConnections()
	response, e := client.Do(req)
	if e != nil {
		return report, ErrTransport
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return report, ErrTransport
	}
	if len(response.Header.Values("Content-Encoding")) > 0 {
		return report, ErrReceipt
	}
	if len(response.Header.Values("Content-Type")) != 1 || (response.Header.Get("Content-Type") != "application/json" && response.Header.Get("Content-Type") != "application/json; charset=utf-8") {
		return report, ErrReceipt
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return report, ErrReceipt
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return report, ErrReceipt
	}
	var acknowledged receipt
	if lanconfig.StrictObject(raw, &acknowledged, "schemaVersion", "agentId", "sequence", "collectedAt", "receivedAt", "duplicate") != nil {
		return report, ErrReceipt
	}
	now := time.Now().UTC()
	if acknowledged.SchemaVersion != "tracebolt.agent-receipt.v1" || acknowledged.AgentID != m.config.AgentID || acknowledged.Sequence != pending.Sequence || !acknowledged.CollectedAt.Equal(f.Observation.Observation.LastSeen) || acknowledged.ReceivedAt.IsZero() || acknowledged.ReceivedAt.After(now.Add(30*time.Second)) || acknowledged.ReceivedAt.Before(acknowledged.CollectedAt.Add(-30*time.Second)) {
		return report, ErrReceipt
	}
	if state.Acknowledge(pending.Digest) != nil {
		return report, ErrState
	}
	report.Status = "acknowledged"
	report.Duplicate = acknowledged.Duplicate
	return report, nil
}
func decodeFrame(raw []byte, sequence uint64) (frame, error) {
	var f frame
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return f, ErrState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil {
		return f, ErrState
	}
	if d.Decode(new(any)) != io.EOF {
		return f, ErrState
	}
	if f.SchemaVersion != FrameVersion || f.Sequence != sequence || f.Observation.SchemaVersion != bundle.SchemaVersion || f.Observation.Product != "Tracebolt" || f.Observation.Platform != f.Observation.Observation.Platform || f.Observation.Scope != "single-read-only-local-observation" {
		return f, ErrState
	}
	if _, e := bundle.Encode(f.Observation.Observation); e != nil {
		return f, ErrState
	}
	return f, nil
}
func stale(f frame, now time.Time) bool {
	d := f.Observation.Observation
	times := []time.Time{f.Observation.GeneratedAt, d.LastSeen, d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt}
	for _, e := range d.Evidence {
		times = append(times, e.CollectedAt)
	}
	for _, at := range times {
		if at.IsZero() || now.Sub(at) > 2*time.Minute || at.Sub(now) > 30*time.Second || at.After(f.Observation.GeneratedAt) {
			return true
		}
	}
	return false
}
