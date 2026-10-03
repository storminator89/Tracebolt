// Package operatorauth supplies bounded authentication for the separate TLS LAN
// operator surface. It never creates an account, writes credentials or listens.
package operatorauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const CookieName = "__Host-tracebolt-session"
const DefaultTTL = 30 * time.Minute

var (
	ErrConfiguration   = errors.New("operator authentication configuration is invalid")
	ErrCredentials     = errors.New("operator credentials are invalid")
	ErrUnauthenticated = errors.New("operator session is missing or expired")
	ErrRateLimited     = errors.New("operator login rate limit reached")
	ErrBusy            = errors.New("operator authentication is busy")
	ErrCapacity        = errors.New("operator session capacity reached")
)

type verifier struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

func parseHash(encoded string) (verifier, error) {
	bad := func() (verifier, error) { return verifier{}, ErrConfiguration }
	if len(encoded) > 256 || strings.TrimSpace(encoded) != encoded {
		return bad()
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return bad()
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return bad()
	}
	values := make([]uint64, 3)
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(params[i], prefix) {
			return bad()
		}
		text := strings.TrimPrefix(params[i], prefix)
		value, err := strconv.ParseUint(text, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != text {
			return bad()
		}
		values[i] = value
	}
	if values[0] < 64*1024 || values[0] > 128*1024 || values[1] < 2 || values[1] > 4 || values[2] < 1 || values[2] > 4 {
		return bad()
	}
	decode := func(s string) ([]byte, error) {
		b, err := base64.RawStdEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawStdEncoding.EncodeToString(b) != s {
			return nil, ErrConfiguration
		}
		return b, nil
	}
	salt, err := decode(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 32 {
		return bad()
	}
	hash, err := decode(parts[5])
	if err != nil || len(hash) != 32 {
		return bad()
	}
	return verifier{uint32(values[0]), uint32(values[1]), uint8(values[2]), salt, hash}, nil
}

type Config struct {
	PasswordHash string `json:"-"`
	TTL          time.Duration
	// Now is a deterministic test seam. Production callers leave it nil.
	Now func() time.Time `json:"-"`
}

func (Config) String() string   { return "operatorauth.Config{secrets:redacted}" }
func (Config) GoString() string { return "operatorauth.Config{secrets:redacted}" }

type Session struct {
	ID        string    `json:"-"`
	Token     string    `json:"-"` // Only a successful Login returns this; never retained in the session map.
	CSRFToken string    `json:"-"`
	ExpiresAt time.Time `json:"expiresAt"`
	revoke    context.CancelFunc
	lifetime  context.Context
	gate      *sessionGate
}

type sessionGate struct {
	mu      sync.RWMutex
	revoked atomic.Bool
	now     func() time.Time
	expires time.Time
}

func (s Session) markRevoked() {
	if s.gate != nil {
		s.gate.revoked.Store(true)
	}
	if s.revoke != nil {
		s.revoke()
	}
}

// BeginMutation linearizes short privileged work against Logout. Release before
// writing a response or waiting on provider/network I/O. Existing admitted work
// finishes before Logout returns; no new work is admitted after revocation/expiry.
func (s Session) BeginMutation(ctx context.Context) (func(), error) {
	if s.gate == nil || ctx.Err() != nil || s.gate.revoked.Load() || !s.gate.now().Before(s.gate.expires) {
		return nil, ErrUnauthenticated
	}
	s.gate.mu.RLock()
	if ctx.Err() != nil || s.gate.revoked.Load() || !s.gate.now().Before(s.gate.expires) {
		s.gate.mu.RUnlock()
		return nil, ErrUnauthenticated
	}
	var once sync.Once
	return func() { once.Do(s.gate.mu.RUnlock) }, nil
}
func (Session) String() string   { return "operatorauth.Session{secrets:redacted}" }
func (Session) GoString() string { return "operatorauth.Session{secrets:redacted}" }

type attempts struct {
	start time.Time
	count int
}
type managerState struct {
	mu       sync.Mutex
	verifier verifier
	now      func() time.Time
	ttl      time.Duration
	sessions map[[32]byte]Session
	peers    map[netip.Addr]attempts
	global   attempts
	hashing  chan struct{}
}

// Copies share state and its mutex; diagnostic formatting redacts both values and pointers.
type Manager struct{ *managerState }

func (Manager) String() string   { return "operatorauth.Manager{secrets:redacted}" }
func (Manager) GoString() string { return "operatorauth.Manager{secrets:redacted}" }
func New(config Config) (*Manager, error) {
	v, err := parseHash(config.PasswordHash)
	if err != nil {
		return nil, err
	}
	ttl := config.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Second || ttl > time.Hour {
		return nil, ErrConfiguration
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{managerState: &managerState{verifier: v, now: now, ttl: ttl, sessions: map[[32]byte]Session{}, peers: map[netip.Addr]attempts{}, hashing: make(chan struct{}, 1)}}, nil
}
func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
func validPassword(value string) bool {
	if len(value) < 12 || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (m *Manager) purgeLocked(now time.Time) {
	for key, s := range m.sessions {
		if !now.Before(s.ExpiresAt) {
			s.markRevoked()
			// Retain the tombstone while an admitted mutation is running so
			// every concurrent Logout waits for the same revocation barrier.
			if s.gate == nil || s.gate.mu.TryLock() {
				if s.gate != nil {
					s.gate.mu.Unlock()
				}
				delete(m.sessions, key)
			}
		}
	}
	for key, a := range m.peers {
		if now.Sub(a.start) >= 2*time.Minute {
			delete(m.peers, key)
		}
	}
}
func (m *Manager) attempt(peer string) error {
	ip, err := netip.ParseAddr(peer)
	if err != nil || ip.Zone() != "" {
		return ErrCredentials
	}
	ip = ip.Unmap()
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
	if m.global.start.IsZero() || now.Sub(m.global.start) >= time.Minute {
		m.global = attempts{start: now}
	}
	state, exists := m.peers[ip]
	if !exists && len(m.peers) >= 512 {
		return ErrRateLimited
	}
	if state.start.IsZero() || now.Sub(state.start) >= time.Minute {
		state = attempts{start: now}
	}
	if state.count >= 5 || m.global.count >= 30 {
		return ErrRateLimited
	}
	state.count++
	m.global.count++
	m.peers[ip] = state
	return nil
}

// Login uses RemoteAddr-derived peer IP only. Header/query values are not peer identity.
func (m *Manager) Login(ctx context.Context, peer, password string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if err := m.attempt(peer); err != nil {
		return Session{}, err
	}
	if !validPassword(password) {
		return Session{}, ErrCredentials
	}
	select {
	case m.hashing <- struct{}{}:
		defer func() { <-m.hashing }()
	default:
		return Session{}, ErrBusy
	}
	secret := []byte(password)
	derived := argon2.IDKey(secret, m.verifier.salt, m.verifier.iterations, m.verifier.memory, m.verifier.parallelism, 32)
	clear(secret)
	valid := subtle.ConstantTimeCompare(derived, m.verifier.hash) == 1
	clear(derived)
	if !valid {
		return Session{}, ErrCredentials
	}
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	token, err := randomHex(32)
	if err != nil {
		return Session{}, ErrBusy
	}
	csrf, err := randomHex(32)
	if err != nil {
		return Session{}, ErrBusy
	}
	id, err := randomHex(16)
	if err != nil {
		return Session{}, ErrBusy
	}
	now := m.now()
	life, revoke := context.WithCancel(context.Background())
	session := Session{ID: id, CSRFToken: csrf, ExpiresAt: now.Add(m.ttl), lifetime: life, revoke: revoke, gate: &sessionGate{now: m.now, expires: now.Add(m.ttl)}}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
	if len(m.sessions) >= 32 {
		revoke()
		return Session{}, ErrCapacity
	}
	m.sessions[sha256.Sum256([]byte(token))] = session
	session.Token = token
	return session, nil
}
func tokenHash(token string) ([32]byte, bool) {
	if len(token) != 64 {
		return [32]byte{}, false
	}
	raw, err := hex.DecodeString(token)
	if err != nil || hex.EncodeToString(raw) != token {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}
func (m *Manager) Lookup(token string) (Session, error) {
	key, ok := tokenHash(token)
	if !ok {
		return Session{}, ErrUnauthenticated
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
	session, ok := m.sessions[key]
	if !ok || session.gate == nil || session.gate.revoked.Load() {
		return Session{}, ErrUnauthenticated
	}
	return session, nil
}
func (m *Manager) Logout(token string) {
	key, ok := tokenHash(token)
	if !ok {
		return
	}
	m.mu.Lock()
	session, ok := m.sessions[key]
	if ok {
		session.markRevoked()
	}
	m.mu.Unlock()
	if ok && session.gate != nil {
		session.gate.mu.Lock()
		session.gate.mu.Unlock()
	}
	// All admitted mutations have drained before removing the tombstone.
	// A concurrent caller either waited for this same gate or now observes
	// a completed revocation, never an unfinished mutation.
	m.mu.Lock()
	delete(m.sessions, key)
	m.mu.Unlock()
}
func (m *Manager) Now() time.Time { return m.now() }

// Lifetime is canceled on logout or expiry cleanup; never derives privileges from a request.
func (s Session) Lifetime() context.Context {
	if s.lifetime == nil {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return s.lifetime
}
