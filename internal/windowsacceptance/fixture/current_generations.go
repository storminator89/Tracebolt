package fixture

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"localrmm/internal/windowsacceptance/profile"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsnetworkcontext"
)

// The four production decoders remain authoritative. This peer implements only
// bounded, ordered, process-local receipt exchange. It is not their SQL store.
var currentDomains = []struct{ path, scope string }{
	{"/v1/windows/agent/full-services/", windowsfullservices.Scope},
	{"/v1/windows/agent/full-software/", windowsfullsoftware.Scope},
	{"/v1/windows/agent/full-processes/", windowsfullprocesses.Scope},
	{"/v1/windows/agent/network-context/", windowsnetworkcontext.Scope},
}

func currentDomain(path string) (string, string) {
	for _, d := range currentDomains {
		for _, op := range []string{"scope", "chunk", "failure"} {
			if path == d.path+op {
				return d.scope, op
			}
		}
	}
	return "", ""
}
func validCurrentGenerationRequest(r *http.Request, origin string, selection profile.Selection) bool {
	if selection != profile.InventoryTLS() || r == nil || r.URL == nil {
		return false
	}
	scope, _ := currentDomain(r.URL.Path)
	if scope == "" {
		return false
	}
	// Reuse every old envelope check without extending its route allowlist.
	copy := *r
	u := *r.URL
	u.Path = selection.TelemetryPath()
	copy.URL = &u
	if r.RequestURI != "" {
		if r.RequestURI != r.URL.Path {
			return false
		}
		copy.RequestURI = u.Path
	}
	return validRequestSelected(&copy, origin, true, selection)
}

type currentConsent struct {
	SchemaVersion string    `json:"schemaVersion"`
	Scope         string    `json:"scope"`
	SenderBinding string    `json:"senderBinding"`
	GrantID       string    `json:"grantId"`
	Revision      uint64    `json:"revision"`
	Enabled       bool      `json:"enabled"`
	ChangedAt     time.Time `json:"changedAt"`
	HistoryScope  string    `json:"historyScope,omitempty"`
}
type currentManifest struct {
	Sequence          uint64    `json:"sequence"`
	CaptureStartedAt  time.Time `json:"captureStartedAt"`
	CaptureFinishedAt time.Time `json:"captureFinishedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	RowCount          int       `json:"rowCount"`
	RowsBytes         int       `json:"rowsBytes"`
	RowsSHA256        string    `json:"rowsSha256"`
	ChunkCount        int       `json:"chunkCount"`
}
type currentMessage struct {
	Operation      string            `json:"operation"`
	DeviceID       string            `json:"deviceId"`
	Consent        currentConsent    `json:"consent"`
	Sequence       uint64            `json:"sequence"`
	Manifest       *currentManifest  `json:"manifest"`
	ManifestSHA256 string            `json:"manifestSha256"`
	Index          int               `json:"index"`
	Offset         int               `json:"offset"`
	Rows           []json.RawMessage `json:"rows"`
	AttemptedAt    *time.Time        `json:"attemptedAt"`
	Reason         string            `json:"reason"`
}
type currentReceipt struct {
	SchemaVersion string    `json:"schemaVersion"`
	Operation     string    `json:"operation"`
	DeviceID      string    `json:"deviceId"`
	GrantID       string    `json:"grantId"`
	GrantRevision uint64    `json:"grantRevision"`
	Sequence      uint64    `json:"sequence"`
	RequestSHA256 string    `json:"requestSha256"`
	Index         int       `json:"index"`
	Status        string    `json:"status"`
	ReceivedAt    time.Time `json:"receivedAt"`
}
type currentGeneration struct {
	consent                                currentConsent
	floor                                  uint64
	captureFloor                           time.Time
	lastAt                                 time.Time
	stagingUntil                           time.Time
	manifestHash                           string
	index, rows, bytes, routes, interfaces int
	digestState                            []byte
	lastOrder                              string // at most one transient service ordering key; never exported
	lastNumeric                            uint64
	seen                                   map[string]bool // hashes of service identity keys, not source labels
	receipts                               map[string]currentReceipt
	scopeReceipt                           currentReceipt
	status                                 string
	projection                             CurrentSourceObservation
}

func decodeCurrentMessage(scope string, raw []byte) (currentMessage, error) {
	var e error
	switch scope {
	case windowsfullservices.Scope:
		_, e = windowsfullservices.DecodeMessage(raw)
	case windowsfullsoftware.Scope:
		_, e = windowsfullsoftware.DecodeMessage(raw)
	case windowsfullprocesses.Scope:
		_, e = windowsfullprocesses.DecodeMessage(raw)
	case windowsnetworkcontext.Scope:
		_, e = windowsnetworkcontext.DecodeMessage(raw)
	default:
		return currentMessage{}, ErrFixture
	}
	if e != nil {
		return currentMessage{}, ErrFixture
	}
	var m currentMessage
	if json.Unmarshal(raw, &m) != nil {
		return currentMessage{}, ErrFixture
	}
	return m, nil
}
func writeCurrentReceipt(w http.ResponseWriter, r currentReceipt) {
	raw, e := json.Marshal(r)
	if e != nil {
		fail(w, 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
func (s *state) currentGeneration(w http.ResponseWriter, r *http.Request, raw []byte) {
	now := s.now().UTC()
	v, e := s.snapshot()
	if e != nil || !s.activeIdentity(v, now) || !s.verifyPeer(r, v, now) {
		fail(w, 403)
		return
	}
	scope, op := currentDomain(r.URL.Path)
	m, e := decodeCurrentMessage(scope, raw)
	if e != nil || m.Operation != op {
		fail(w, 400)
		return
	}
	if m.DeviceID != v.Approval.DeviceID || m.Consent.SenderBinding != windowsfullprocesses.SenderBinding("tls", s.bootstrap.AgentOrigin, v.Issuance.CertificateHash, m.DeviceID) || m.Consent.ChangedAt.After(now) || m.Consent.ChangedAt.Unix() < v.Activation.At {
		fail(w, 403)
		return
	}
	hash := digest(raw)
	g := s.currentGenerations[scope]
	if g == nil {
		g = &currentGeneration{receipts: map[string]currentReceipt{}, seen: map[string]bool{}}
	}
	if !g.lastAt.IsZero() && now.Before(g.lastAt) {
		fail(w, 409)
		return
	}
	if m.Manifest != nil && (m.Manifest.CaptureFinishedAt.After(now) || !now.Before(m.Manifest.ExpiresAt)) || m.AttemptedAt != nil && (m.AttemptedAt.After(now) || !now.Before(m.AttemptedAt.Add(24*time.Hour))) {
		fail(w, 409)
		return
	}
	if op == "chunk" && g.status == "pending" && m.ManifestSHA256 == g.manifestHash && !now.Before(g.stagingUntil) {
		fail(w, 409)
		return
	}
	if op == "scope" && g.scopeReceipt.RequestSHA256 == hash {
		writeCurrentReceipt(w, g.scopeReceipt)
		return
	}
	if receipt, ok := g.receipts[hash]; ok {
		if now.Before(receipt.ReceivedAt) {
			fail(w, 409)
			return
		}
		writeCurrentReceipt(w, receipt)
		return
	}
	// Fresh profile only: never adopt, replace, disable/re-enable or promote an
	// existing consent inside this disposable acceptance fixture.
	if op == "scope" {
		if g.consent.Revision != 0 || !m.Consent.Enabled {
			fail(w, 409)
			return
		}
	} else if m.Consent != g.consent || !g.consent.Enabled {
		fail(w, 409)
		return
	}
	next := *g
	next.receipts = make(map[string]currentReceipt, len(g.receipts)+1)
	for k, x := range g.receipts {
		next.receipts[k] = x
	}
	next.seen = make(map[string]bool, len(g.seen))
	for k, x := range g.seen {
		next.seen[k] = x
	}
	projection := *s.currentObservation.source(scope)
	status := "accepted"
	switch op {
	case "scope":
		next.consent = m.Consent
		next.status = "scope"
		projection.Status = "scope"
	case "failure":
		if m.Sequence <= g.floor || !g.captureFloor.IsZero() && !m.AttemptedAt.After(g.captureFloor) {
			fail(w, 409)
			return
		}
		next.floor = m.Sequence
		next.captureFloor = *m.AttemptedAt
		next.manifestHash = ""
		next.digestState = nil
		next.lastOrder = ""
		next.seen = map[string]bool{}
		next.receipts = map[string]currentReceipt{}
		next.status = "source_failed"
		projection.Status = "source_failed"
		projection.Reason = m.Reason
		projection.Samples++
		projection.Rows = 0
		projection.Qualities = CurrentQualityCounts{}
		projection.CompleteFields = 0
		projection.TruncatedFields = 0
		switch m.Reason {
		case "access_denied":
			projection.Qualities.Denied = 1
		case "unsupported":
			projection.Qualities.Unsupported = 1
		default:
			projection.Qualities.Unavailable = 1
		}
	case "chunk":
		if m.Sequence != g.floor || m.ManifestSHA256 != g.manifestHash {
			if g.status == "pending" && now.Before(g.stagingUntil) || m.Sequence <= g.floor || m.Index != 0 || !g.captureFloor.IsZero() && !m.Manifest.CaptureStartedAt.After(g.captureFloor) {
				fail(w, 409)
				return
			}
			next.floor = m.Sequence
			next.captureFloor = m.Manifest.CaptureStartedAt
			next.manifestHash = m.ManifestSHA256
			next.stagingUntil = now.Add(15 * time.Minute)
			next.index = 0
			next.rows = 0
			next.bytes = 2
			next.routes = 0
			next.interfaces = 0
			next.lastOrder = ""
			next.lastNumeric = 0
			next.seen = map[string]bool{}
			next.receipts = map[string]currentReceipt{}
			next.projection = CurrentSourceObservation{}
			projection.Rows = 0
			projection.Qualities = CurrentQualityCounts{}
			projection.CompleteFields = 0
			projection.TruncatedFields = 0
			h := sha256.New()
			_, _ = h.Write([]byte("tracebolt." + strings.TrimSuffix(scope, "-v1") + ".rows.v1\x00["))
			next.digestState, _ = h.(encoding.BinaryMarshaler).MarshalBinary()
		}
		if m.Index != next.index || m.Offset != next.rows || next.status == "complete" && m.Sequence == g.floor {
			fail(w, 409)
			return
		}
		h := sha256.New()
		if h.(encoding.BinaryUnmarshaler).UnmarshalBinary(next.digestState) != nil {
			fail(w, 409)
			return
		}
		for _, row := range m.Rows {
			if !next.rowIdentity(scope, row) {
				fail(w, 400)
				return
			}
			if next.rows > 0 {
				_, _ = h.Write([]byte(","))
				next.bytes++
			}
			_, _ = h.Write(row)
			next.bytes += len(row)
			next.rows++
			var value any
			_ = json.Unmarshal(row, &value)
			projectValue(value, &next.projection)
		}
		next.index++
		next.status = "pending"
		projection.Status = "pending"
		projection.Reason = ""
		if next.index == m.Manifest.ChunkCount {
			_, _ = h.Write([]byte("]"))
			if next.rows != m.Manifest.RowCount || next.bytes != m.Manifest.RowsBytes || hex.EncodeToString(h.Sum(nil)) != m.Manifest.RowsSHA256 {
				fail(w, 400)
				return
			}
			status = "complete"
			next.status = "complete"
			projection.Status = "complete"
			projection.Samples++
			projection.Rows = uint32(next.rows)
			projection.Qualities = next.projection.Qualities
			projection.CompleteFields = 1
			projection.TruncatedFields = 0
			next.digestState = nil
			next.lastOrder = ""
			next.seen = map[string]bool{}
		} else {
			next.digestState, _ = h.(encoding.BinaryMarshaler).MarshalBinary()
		}
	}
	// Check authority, original deadlines and monotonic clock again immediately
	// before publishing metadata and the exact receipt under the shared lock.
	fresh := s.now().UTC()
	if fresh.Before(now) || op == "chunk" && !fresh.Before(next.stagingUntil) || !s.activeIdentity(v, fresh) || !s.verifyPeer(r, v, fresh) || r.Context().Err() != nil || m.Manifest != nil && !fresh.Before(m.Manifest.ExpiresAt) || m.AttemptedAt != nil && !fresh.Before(m.AttemptedAt.Add(24*time.Hour)) {
		fail(w, 403)
		return
	}
	receipt := currentReceipt{"tracebolt." + strings.TrimSuffix(scope, "-v1") + "-receipt.v1", op, m.DeviceID, m.Consent.GrantID, m.Consent.Revision, m.Sequence, hash, m.Index, status, now}
	if op == "scope" {
		next.scopeReceipt = receipt
	} else {
		next.receipts[hash] = receipt
	}
	next.lastAt = now
	projection.Frames++
	projection.LastSequence = m.Sequence
	if op == "scope" {
		projection.LastSequence = m.Consent.Revision
	}
	projection.LastFrameSHA256 = hash
	s.currentGenerations[scope] = &next
	*s.currentObservation.source(scope) = projection
	writeCurrentReceipt(w, receipt)
}
func (g *currentGeneration) rowIdentity(scope string, raw []byte) bool {
	var key struct {
		Name           string `json:"name"`
		RegistrationID string `json:"registrationId"`
		PID            uint64 `json:"pid"`
		ID             uint64 `json:"id"`
		Kind           string `json:"kind"`
	}
	// Software/process names may be null, which is intentionally allowed here;
	// their authoritative source decoder already checked all field semantics.
	if json.Unmarshal(raw, &key) != nil {
		return false
	}
	switch scope {
	case windowsfullservices.Scope:
		h := digest([]byte(windowsfullservices.IdentityKey(key.Name)))
		if g.rows > 0 && key.Name <= g.lastOrder || g.seen[h] {
			return false
		}
		g.seen[h] = true
		g.lastOrder = key.Name
	case windowsfullsoftware.Scope:
		if g.rows > 0 && key.RegistrationID <= g.lastOrder {
			return false
		}
		g.lastOrder = key.RegistrationID
	case windowsfullprocesses.Scope:
		if g.rows > 0 && key.PID <= g.lastNumeric {
			return false
		}
		g.lastNumeric = key.PID
	case windowsnetworkcontext.Scope:
		if g.rows > 0 && key.ID <= g.lastNumeric {
			return false
		}
		g.lastNumeric = key.ID
		if key.Kind == "route" {
			g.routes++
		} else {
			g.interfaces++
		}
		if g.routes > windowsnetworkcontext.MaxRoutes || g.interfaces > windowsnetworkcontext.MaxInterfaces {
			return false
		}
	default:
		return false
	}
	return true
}
