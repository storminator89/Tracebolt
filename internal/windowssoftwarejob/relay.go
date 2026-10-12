package windowssoftwarejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const RelayVersion = "tracebolt.windows-prepared-msi-relay.v1"
const MaxRelayBytes = 16384

// Challenge is a manager-signed exact, short-lived readiness request. A relay
// cannot substitute the endpoint, executor key, package or original deadline.
type Challenge struct {
	Version   string    `json:"version"`
	Binding   Binding   `json:"binding"`
	JobID     string    `json:"jobId"`
	Selection Selection `json:"selection"`
	IssuedAt  int64     `json:"issuedAt"`
	// Independent of the bounded approved-install sequence.
	Sequence uint64 `json:"sequence,string"`
	Deadline int64  `json:"deadline"`
}

func (c Challenge) Validate() error {
	if c.Version != RelayVersion || c.Sequence == 0 || !ValidBinding(c.Binding) || !enrollmentcrypto.ValidID(c.JobID, "software_") || !ValidSelection(c.Selection) || !validTime(c.IssuedAt) || !validTime(c.Deadline) || c.Deadline <= c.IssuedAt || c.Deadline-c.IssuedAt > 120 {
		return ErrInvalid
	}
	return nil
}

type challengeEnvelope struct {
	Challenge Challenge `json:"challenge"`
	Signature string    `json:"signature"`
}

func challengeMessage(c Challenge) []byte {
	raw, _ := json.Marshal(c)
	return append([]byte("Tracebolt prepared MSI readiness request v1\x00"), raw...)
}
func SignChallenge(c Challenge, k ed25519.PrivateKey) ([]byte, error) {
	if c.Validate() != nil || len(k) != ed25519.PrivateKeySize || !bytes.Equal(k, ed25519.NewKeyFromSeed(k[:32])) || actionpermit.Digest(k.Public().(ed25519.PublicKey)) != c.Binding.KeyID {
		return nil, ErrInvalid
	}
	return json.Marshal(challengeEnvelope{c, base64.RawStdEncoding.EncodeToString(ed25519.Sign(k, challengeMessage(c)))})
}
func VerifyChallenge(raw []byte, key ed25519.PublicKey) (Challenge, error) {
	var e challengeEnvelope
	if !keyvalidation.Ed25519(key) || canonical(raw, &e, MaxRelayBytes) != nil || e.Challenge.Validate() != nil || e.Challenge.Binding.KeyID != actionpermit.Digest(key) {
		return Challenge{}, ErrInvalid
	}
	sig, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(sig) != e.Signature || !ed25519.Verify(key, challengeMessage(e.Challenge), sig) {
		return Challenge{}, ErrAuthority
	}
	return e.Challenge, nil
}

// Statement is executor-authenticated metadata relayed by the observer over its
// CURRENT TLS leaf. ReferenceDigest commits the exact readiness challenge or
// install permit, and Deadline is that original request's finite deadline.
// Result messages may arrive after dispatch expiry; they never renew authority.
type Statement struct {
	Version         string     `json:"version"`
	Kind            string     `json:"kind"`
	Binding         Binding    `json:"binding"`
	JobID           string     `json:"jobId"`
	ReferenceDigest string     `json:"referenceDigest"`
	Deadline        int64      `json:"deadline"`
	IssuedAt        int64      `json:"issuedAt"`
	ExpiresAt       int64      `json:"expiresAt"`
	Readiness       *Readiness `json:"readiness"`
	Result          *Result    `json:"result"`
}

func (s Statement) Validate() error {
	if s.Version != RelayVersion || !ValidBinding(s.Binding) || !enrollmentcrypto.ValidID(s.JobID, "software_") || !actionpermit.ValidDigest(s.ReferenceDigest) || !validTime(s.Deadline) || !validTime(s.IssuedAt) || !validTime(s.ExpiresAt) || s.ExpiresAt <= s.IssuedAt || s.ExpiresAt-s.IssuedAt > 300 {
		return ErrInvalid
	}
	switch s.Kind {
	case "readiness":
		if s.Readiness == nil || s.Result != nil || s.Readiness.Validate() != nil || s.Readiness.CapturedAt != s.IssuedAt || s.ExpiresAt > s.Deadline || s.ExpiresAt-s.IssuedAt > 60 {
			return ErrInvalid
		}
	case "result":
		if s.Readiness != nil || s.Result == nil || s.Result.Validate() != nil || s.Result.JobID != s.JobID || s.Result.EnvelopeDigest != s.ReferenceDigest || s.Result.CompletedAt != s.IssuedAt {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type statementEnvelope struct {
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"`
}

func statementMessage(s Statement) []byte {
	raw, _ := json.Marshal(s)
	return append([]byte("Tracebolt dedicated MSI executor statement v1\x00"), raw...)
}
func SignStatement(s Statement, k ed25519.PrivateKey) ([]byte, error) {
	if s.Validate() != nil || len(k) != ed25519.PrivateKeySize || !bytes.Equal(k, ed25519.NewKeyFromSeed(k[:32])) || s.Binding.ExecutorKeyID != actionpermit.Digest(k.Public().(ed25519.PublicKey)) {
		return nil, ErrInvalid
	}
	return json.Marshal(statementEnvelope{s, base64.RawStdEncoding.EncodeToString(ed25519.Sign(k, statementMessage(s)))})
}
func VerifyStatement(raw []byte, key ed25519.PublicKey) (Statement, error) {
	var e statementEnvelope
	if !keyvalidation.Ed25519(key) || canonical(raw, &e, MaxRelayBytes) != nil || e.Statement.Validate() != nil || e.Statement.Binding.ExecutorKeyID != actionpermit.Digest(key) {
		return Statement{}, ErrInvalid
	}
	sig, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(sig) != e.Signature || !ed25519.Verify(key, statementMessage(e.Statement), sig) {
		return Statement{}, ErrAuthority
	}
	return e.Statement, nil
}

// Pending is metadata only. No signed execution/readiness envelope is exposed.
type Pending struct {
	JobID    string `json:"jobId"`
	Kind     string `json:"kind"`
	Deadline int64  `json:"deadline"`
}

func (m *Manager) Pending(ctx context.Context) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out *Pending
	e := m.transaction(ctx, func(c Current, n int64) error {
		for _, j := range m.record.Jobs {
			if j.State == "requested" && j.ReadinessClaimedAt == 0 {
				c, e := VerifyChallenge(j.Challenge, m.record.PublicKey)
				if e != nil {
					return e
				}
				if n < c.Deadline {
					out = &Pending{j.ID, "readiness", c.Deadline}
					return nil
				}
			}
			if j.State == "approved" && n < j.Preview.ExpiresAt {
				out = &Pending{j.ID, "install", j.Preview.ExpiresAt}
				return nil
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (m *Manager) ClaimReadiness(ctx context.Context, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []byte
	e := m.transaction(ctx, func(_ Current, n int64) error {
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != id {
				continue
			}
			if j.State != "requested" || j.ReadinessClaimedAt != 0 {
				return ErrConsumed
			}
			c, e := VerifyChallenge(j.Challenge, m.record.PublicKey)
			if e != nil {
				return e
			}
			if n >= c.Deadline {
				return ErrExpired
			}
			j.ReadinessClaimedAt = n
			if e = m.save(n); e != nil {
				return e
			}
			out = bytes.Clone(j.Challenge)
			return nil
		}
		return ErrConflict
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}

// Report admits a pinned executor signature AND the surrounding enrollment
// transaction's live leaf. Transport authentication alone is insufficient.
func (m *Manager) Report(ctx context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.transaction(ctx, func(c Current, n int64) error {
		s, e := VerifyStatement(raw, m.record.ExecutorPublicKey)
		if e != nil {
			return e
		}
		if s.Binding != m.Binding() {
			return ErrAuthority
		}
		for i := range m.record.Jobs {
			j := &m.record.Jobs[i]
			if j.ID != s.JobID {
				continue
			}
			if s.Kind == "result" {
				if bytes.Equal(j.ResultReport, raw) && j.Result != nil {
					return nil
				}
				if j.State != "claimed" || s.ReferenceDigest != actionpermit.Digest(j.Envelope) || s.Deadline != j.Preview.ExpiresAt || s.IssuedAt < j.ClaimedAt {
					return ErrConflict
				}
				if s.IssuedAt > n || n >= s.ExpiresAt {
					return ErrExpired
				}
				j.Result = s.Result
				j.ResultReport = bytes.Clone(raw)
				j.State = "complete"
				return m.save(n)
			}
			if bytes.Equal(j.ReadinessReport, raw) && j.Preview != nil {
				return nil
			}
			challenge, e := VerifyChallenge(j.Challenge, m.record.PublicKey)
			if e != nil {
				return e
			}
			if j.State != "requested" || j.ReadinessClaimedAt == 0 || s.ReferenceDigest != actionpermit.Digest(j.Challenge) || s.Deadline != challenge.Deadline || s.Readiness.Selection != j.Selection || s.IssuedAt < j.ReadinessClaimedAt {
				return ErrConflict
			}
			if s.IssuedAt > n || n >= s.ExpiresAt || n >= challenge.Deadline {
				return ErrExpired
			}
			p := Preview{ID: j.ID, ActorID: j.ActorID, Binding: m.Binding(), Readiness: *s.Readiness, CreatedAt: n, ExpiresAt: min(s.ExpiresAt, c.LeafNotAfter, m.record.Consent.ExpiresAt, s.Readiness.MaintenanceWindowEnd)}
			p.Digest = previewDigest(p)
			if p.Validate() != nil {
				return ErrInvalid
			}
			j.Preview = &p
			j.ReadinessReport = bytes.Clone(raw)
			j.State = "blocked"
			j.Reason = p.Readiness.Reason()
			if j.Reason == "ready" {
				j.State = "preview"
			}
			return m.save(n)
		}
		return ErrConflict
	})
}

// Review explicitly reopens only the exact saved unsigned preview, with its
// original digest/age, for the same authenticated operator. It never re-resolves.
func (m *Manager) Review(ctx context.Context, device, actor, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if device != m.Binding().DeviceID {
		return ErrInvalid
	}
	return m.transaction(ctx, func(_ Current, n int64) error {
		for _, j := range m.record.Jobs {
			if j.ID == id && j.ActorID == actor && j.State == "preview" && j.Preview != nil && n < j.Preview.ExpiresAt {
				return nil
			}
		}
		return ErrExpired
	})
}
