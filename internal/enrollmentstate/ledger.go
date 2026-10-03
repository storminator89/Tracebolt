package enrollmentstate

// This file is the private persistence boundary used by enrollmentstore. It is
// deliberately separate from inspection JSON: a snapshot can never restore an
// invitation verifier or the key that was proved at claim time. Only the trusted
// local storage adapter may use this codec. It is not an import/backup API.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const MaxTrustedLedgerBytes = MaxRecords*(MaxJSONBytes+256) + 4096
const ledgerMagic = "tracebolt.private-enrollment-ledger.v1\x00"

// EncodeTrustedLedger exports secret verifier material for an already protected
// database transaction. Never expose, log, or send its result to an endpoint.
func (e *Engine) EncodeTrustedLedger() ([]byte, error) {
	if e == nil || e.engineState == nil {
		return nil, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var out bytes.Buffer
	out.WriteString(ledgerMagic)
	config, err := json.Marshal(e.config)
	if err != nil {
		return nil, ErrInvalid
	}
	writeLedgerFrame(&out, config)
	ids := make([]string, 0, len(e.records))
	for id := range e.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	binary.Write(&out, binary.BigEndian, uint32(len(ids)))
	for _, id := range ids {
		r := e.records[id]
		raw, err := EncodeSnapshot(r.snapshot)
		if err != nil {
			return nil, err
		}
		writeLedgerFrame(&out, raw)
		out.Write(r.verifier[:])
		writeLedgerFrame(&out, []byte(r.publicKeyDERBase64))
	}
	if out.Len() > MaxTrustedLedgerBytes {
		return nil, ErrInvalid
	}
	return out.Bytes(), nil
}
func writeLedgerFrame(w *bytes.Buffer, b []byte) {
	binary.Write(w, binary.BigEndian, uint32(len(b)))
	w.Write(b)
}
func readLedgerFrame(r *bytes.Reader, limit uint32) ([]byte, error) {
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil || n > limit || uint64(n) > uint64(r.Len()) {
		return nil, ErrInvalid
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

// RestoreTrustedLedger validates a complete private ledger under an exact local
// configuration. The adapter must hold its database write transaction from this
// read through the transition, credential persistence and commit. The returned
// Engine must remain transaction-local; it is never a durable shared cache.
func RestoreTrustedLedger(config Config, raw []byte) (*Engine, error) {
	e, err := New(config)
	if err != nil || len(raw) < len(ledgerMagic)+8 || len(raw) > MaxTrustedLedgerBytes || string(raw[:len(ledgerMagic)]) != ledgerMagic {
		return nil, ErrInvalid
	}
	r := bytes.NewReader(raw[len(ledgerMagic):])
	header, err := readLedgerFrame(r, 2048)
	if err != nil {
		return nil, ErrInvalid
	}
	expected, _ := json.Marshal(config)
	if !bytes.Equal(header, expected) {
		return nil, ErrInvalid
	}
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil || n > uint32(config.RecordLimit) {
		return nil, ErrInvalid
	}
	unique := make(map[string]bool)
	add := func(kind, v string) bool {
		if v == "" {
			return true
		}
		k := kind + ":" + v
		if unique[k] {
			return false
		}
		unique[k] = true
		return true
	}
	previous := ""
	for range n {
		body, err := readLedgerFrame(r, MaxJSONBytes)
		if err != nil {
			return nil, ErrInvalid
		}
		s, err := DecodeSnapshot(body)
		if err != nil || s.Binding != config.Binding || s.InvitationID <= previous {
			return nil, ErrInvalid
		}
		previous = s.InvitationID
		rec := record{snapshot: s}
		if _, err := io.ReadFull(r, rec.verifier[:]); err != nil || rec.verifier == ([32]byte{}) {
			return nil, ErrInvalid
		}
		key, err := readLedgerFrame(r, 172)
		if err != nil {
			return nil, ErrInvalid
		}
		rec.publicKeyDERBase64 = string(key)
		stageN := stage(s.State)
		revision := stageN
		if terminal(s.State) {
			stageN = stage(s.Termination.From)
			revision = stageN + 1
		}
		if s.Revision != uint64(revision) {
			return nil, ErrInvalid
		}
		if stageN == 1 {
			if rec.publicKeyDERBase64 != "" || s.DeadlineAt != s.CreatedAt+config.InvitationTTL {
				return nil, ErrInvalid
			}
		} else {
			if s.Claim.At >= s.CreatedAt+config.InvitationTTL || s.DeadlineAt != s.Claim.At+config.PendingTTL || !validLedgerKey(rec) {
				return nil, ErrInvalid
			}
		}
		if stageN >= 4 && validateSigningIntent(rec, s) != nil {
			return nil, ErrInvalid
		}
		if !add("verifier", hex.EncodeToString(rec.verifier[:])) || !add("claim", s.Claim.ClaimID) || !add("agent", s.Approval.DeviceID) || !add("intent", s.Intent.IntentID) || !add("serial", s.Intent.SerialHex) || !add("certificate", s.Issuance.CertificateHash) {
			return nil, ErrInvalid
		}
		for _, id := range []string{s.CreateRequestID, s.Claim.RequestID, s.Approval.RequestID, s.Intent.RequestID, s.Issuance.RequestID, s.Activation.RequestID, s.Termination.RequestID} {
			if !add("request", id) {
				return nil, ErrInvalid
			}
		}
		e.records[s.InvitationID] = rec
	}
	if r.Len() != 0 || e.count(Created) > config.InvitationLimit || e.pendingCount() > config.PendingLimit {
		return nil, ErrInvalid
	}
	return e, nil
}
func validLedgerKey(r record) bool {
	der, err := base64.RawStdEncoding.Strict().DecodeString(r.publicKeyDERBase64)
	if err != nil || len(der) > 128 || base64.RawStdEncoding.EncodeToString(der) != r.publicKeyDERBase64 {
		return false
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != r.snapshot.Claim.KeyFingerprint {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(key) {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	return err == nil && bytes.Equal(canonical, der)
}

// TrustedRecordedIntent reconstructs immutable issuance metadata for local
// storage validation. It grants no authority to sign, deliver, activate, or
// resurrect a terminal record. Use SigningIntent for signing authorization.
func (e *Engine) TrustedRecordedIntent(id string) (enrollmentcrypto.Intent, error) {
	if e == nil || e.engineState == nil || !validID(id, "invite") {
		return enrollmentcrypto.Intent{}, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[id]
	if !ok {
		return enrollmentcrypto.Intent{}, ErrNotFound
	}
	n := stage(r.snapshot.State)
	if terminal(r.snapshot.State) {
		n = stage(r.snapshot.Termination.From)
	}
	if n < 4 || validateSigningIntent(r, r.snapshot) != nil {
		return enrollmentcrypto.Intent{}, ErrState
	}
	return expectedIntent(r), nil
}

// TrustedClaimKey is a protected local verification lookup, not a proof or
// lifecycle authorization. The durable adapter must recheck the verified result
// in its final transaction. No invitation verifier is exposed.
func (e *Engine) TrustedClaimKey(id string) ([]byte, error) {
	if e == nil || e.engineState == nil || !validID(id, "invite") {
		return nil, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !validLedgerKey(r) {
		return nil, ErrState
	}
	der, err := base64.RawStdEncoding.DecodeString(r.publicKeyDERBase64)
	if err != nil {
		return nil, ErrInvalid
	}
	return der, nil
}
