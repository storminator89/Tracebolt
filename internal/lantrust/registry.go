package lantrust

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxAgents = 1000
const MaxLabelBytes = 120

var (
	ErrUnauthorized        = errors.New("agent certificate is not authorized")
	ErrAlreadyApproved     = errors.New("certificate was already approved; renewed certificates require a new approval")
	ErrNotFound            = errors.New("agent approval not found")
	ErrRegistryUnavailable = errors.New("agent approval storage is unavailable")
	ErrCapacity            = errors.New("agent approval registry is full")
)

// Agent is a public-only descriptor. Names from certificates and request bodies
// never become IDs. A revoked fingerprint can never be reapproved or reassigned.
type Agent struct {
	ID                string    `json:"id"`
	Label             string    `json:"label"`
	FingerprintSHA256 string    `json:"fingerprintSHA256"`
	ApprovedAt        time.Time `json:"approvedAt"`
	NotBefore         time.Time `json:"notBefore"`
	ExpiresAt         time.Time `json:"expiresAt"`
	RevokedAt         time.Time `json:"revokedAt"`
}

// Store persists public descriptors only. Save must atomically insert or update
// one Agent, retain other rows, and return only after durable commit. It must
// reject ID/fingerprint reassignment and never remove revocation tombstones.
// Exactly one Registry/process owns a Store; external edits and shared writers
// are unsupported. Load must return all records (no pagination/truncation).
type Store interface {
	Load(context.Context) ([]Agent, error)
	Save(context.Context, Agent) error
}

type Registry struct {
	mu            sync.RWMutex
	roots         *x509.CertPool
	store         Store
	byID          map[string]Agent
	byFingerprint map[string]string
	unavailable   bool
	now           func() time.Time
}

// NewRegistry validates explicit CA material and every stored approval before
// returning. A missing, corrupt or unreadable Store never means empty trust.
func NewRegistry(ctx context.Context, caPEM []byte, store Store) (*Registry, error) {
	if store == nil {
		return nil, ErrConfiguration
	}
	roots, err := certificatePool(caPEM, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	rows, err := store.Load(ctx)
	if err != nil {
		return nil, ErrRegistryUnavailable
	}
	if len(rows) > MaxAgents {
		return nil, ErrCapacity
	}
	r := &Registry{roots: roots, store: store, byID: make(map[string]Agent), byFingerprint: make(map[string]string), now: func() time.Time { return time.Now().UTC() }}
	for _, a := range rows {
		if !validDescriptor(a) {
			return nil, ErrConfiguration
		}
		if _, exists := r.byID[a.ID]; exists {
			return nil, ErrConfiguration
		}
		if _, exists := r.byFingerprint[a.FingerprintSHA256]; exists {
			return nil, ErrConfiguration
		}
		r.byID[a.ID] = a
		r.byFingerprint[a.FingerprintSHA256] = a.ID
	}
	return r, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > MaxLabelBytes || !utf8.ValidString(label) || strings.TrimSpace(label) != label {
		return false
	}
	for _, ch := range label {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
}
func validHex(s string, n int) bool {
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == n && hex.EncodeToString(decoded) == s
}
func validDescriptor(a Agent) bool {
	return strings.HasPrefix(a.ID, "agent_") && validHex(strings.TrimPrefix(a.ID, "agent_"), 16) && validHex(a.FingerprintSHA256, 32) && validLabel(a.Label) &&
		!a.ApprovedAt.IsZero() && !a.NotBefore.IsZero() && a.NotBefore.Before(a.ExpiresAt) && !a.ApprovedAt.Before(a.NotBefore) && a.ApprovedAt.Before(a.ExpiresAt) && (a.RevokedAt.IsZero() || !a.RevokedAt.Before(a.ApprovedAt))
}

// Approve must be called only from an authenticated, CSRF-protected operator
// action after an out-of-band device/fingerprint check. It is not enrollment.
func (r *Registry) Approve(ctx context.Context, publicPEM []byte, label string) (Agent, error) {
	if !validLabel(label) {
		return Agent{}, ErrConfiguration
	}
	certs, err := parsePublicCertificates(publicPEM)
	if err != nil {
		return Agent{}, err
	}
	now := r.now()
	if err := verifyAgentChain(certs, r.roots, now); err != nil {
		return Agent{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unavailable {
		return Agent{}, ErrRegistryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Agent{}, err
	}
	fingerprint := Fingerprint(certs[0])
	if _, exists := r.byFingerprint[fingerprint]; exists {
		return Agent{}, ErrAlreadyApproved
	}
	if len(r.byID) >= MaxAgents {
		return Agent{}, ErrCapacity
	}
	var id string
	for {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return Agent{}, ErrRegistryUnavailable
		}
		id = "agent_" + hex.EncodeToString(random[:])
		if _, exists := r.byID[id]; !exists {
			break
		}
	}
	a := Agent{ID: id, Label: label, FingerprintSHA256: fingerprint, ApprovedAt: now, NotBefore: certs[0].NotBefore.UTC(), ExpiresAt: certs[0].NotAfter.UTC()}
	if err := r.store.Save(ctx, a); err != nil {
		// A storage error can have an uncertain commit outcome. Stop admitting all
		// telemetry rather than continue with a potentially stale approval view.
		r.unavailable = true
		return Agent{}, ErrRegistryUnavailable
	}
	r.byID[id], r.byFingerprint[fingerprint] = a, id
	return a, nil
}

// Revoke is idempotent and retains a permanent tombstone. On durable-write error
// the entire live registry fails closed; operators must resolve persistence and
// ensure the tombstone is durably saved before deliberate reload/recovery.
func (r *Registry) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unavailable {
		return ErrRegistryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a, exists := r.byID[id]
	if !exists {
		return ErrNotFound
	}
	if !a.RevokedAt.IsZero() {
		return nil
	}
	a.RevokedAt = r.now()
	if a.RevokedAt.Before(a.ApprovedAt) {
		return ErrConfiguration
	}
	if err := r.store.Save(ctx, a); err != nil {
		r.unavailable = true
		return ErrRegistryUnavailable
	}
	r.byID[id] = a
	return nil
}

// List is an immutable, deterministic snapshot including revoked approvals.
func (r *Registry) List() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Agent, 0, len(r.byID))
	for _, a := range r.byID {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Authenticate rechecks certificate validity, configured roots and live approval
// on EVERY request, including requests on reused TLS connections. Forwarded
// headers, certificate names, hostnames and body IDs are not identity sources.
// A request authenticated before Revoke's commit may finish; all later auth
// decisions see the revocation. Call only with the TLS request from net/http.
func (r *Registry) Authenticate(req *http.Request) (Agent, error) {
	if req == nil || req.TLS == nil || !req.TLS.HandshakeComplete || req.TLS.Version < tls.VersionTLS13 || len(req.TLS.PeerCertificates) == 0 || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 || Fingerprint(req.TLS.VerifiedChains[0][0]) != Fingerprint(req.TLS.PeerCertificates[0]) {
		return Agent{}, ErrUnauthorized
	}
	now := r.now()
	if err := verifyAgentChain(req.TLS.PeerCertificates, r.roots, now); err != nil {
		return Agent{}, ErrUnauthorized
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.unavailable {
		return Agent{}, ErrRegistryUnavailable
	}
	a, exists := r.byID[r.byFingerprint[Fingerprint(req.TLS.PeerCertificates[0])]]
	if !exists || !a.RevokedAt.IsZero() || now.Before(a.NotBefore) || !now.Before(a.ExpiresAt) {
		return Agent{}, ErrUnauthorized
	}
	return a, nil
}

type contextKey struct{}

// FromContext returns the only identity a telemetry handler may use. Any claimed
// device ID must be rejected or ignored, never used to select a storage record.
func FromContext(ctx context.Context) (Agent, bool) {
	a, ok := ctx.Value(contextKey{}).(Agent)
	return a, ok
}

func (r *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a, err := r.Authenticate(req)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			status := http.StatusUnauthorized
			if errors.Is(err, ErrRegistryUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, "agent authentication rejected", status)
			return
		}
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), contextKey{}, a)))
	})
}

// MemoryStore is an explicitly ephemeral test/development store. A LAN pilot
// requires a protected durable Store; this never writes a file or a credential.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[string]Agent
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{rows: make(map[string]Agent)} }
func (s *MemoryStore) Load(ctx context.Context) ([]Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(s.rows))
	for _, a := range s.rows {
		out = append(out, a)
	}
	return out, nil
}
func (s *MemoryStore) Save(ctx context.Context, a Agent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validDescriptor(a) {
		return ErrConfiguration
	}
	if old, exists := s.rows[a.ID]; exists {
		if a.FingerprintSHA256 != old.FingerprintSHA256 || a.Label != old.Label || !a.ApprovedAt.Equal(old.ApprovedAt) || !a.NotBefore.Equal(old.NotBefore) || !a.ExpiresAt.Equal(old.ExpiresAt) || (!old.RevokedAt.IsZero() && !old.RevokedAt.Equal(a.RevokedAt)) {
			return ErrConfiguration
		}
	}
	for id, old := range s.rows {
		if id != a.ID && old.FingerprintSHA256 == a.FingerprintSHA256 {
			return ErrConfiguration
		}
	}
	if s.rows == nil {
		s.rows = make(map[string]Agent)
	}
	s.rows[a.ID] = a
	return nil
}
