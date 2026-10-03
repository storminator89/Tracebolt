package operatorauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

const fixturePassword = "fixture-only-password-not-real"

var fixtureOnce sync.Once
var fixtureEncoded string

func fixtureHash() string {
	fixtureOnce.Do(func() {
		salt := []byte("fixture-salt-1234")
		hash := argon2.IDKey([]byte(fixturePassword), salt, 2, 65536, 1, 32)
		fixtureEncoded = fmt.Sprintf("$argon2id$v=19$m=65536,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
	})
	return fixtureEncoded
}
func manager(t *testing.T, now func() time.Time) *Manager {
	t.Helper()
	m, err := New(Config{PasswordHash: fixtureHash(), Now: now})
	if err != nil {
		t.Fatal("fixture auth configuration rejected")
	}
	return m
}
func TestConfigurationFailClosedAndBounded(t *testing.T) {
	valid := fixtureHash()
	for _, hash := range []string{"", strings.Replace(valid, "argon2id", "argon2i", 1), strings.Replace(valid, "v=19", "v=16", 1), strings.Replace(valid, "m=65536", "m=4294967295", 1), strings.Replace(valid, "m=65536", "m=1024", 1), strings.Replace(valid, "t=2", "t=999", 1), strings.Replace(valid, "p=1", "p=255", 1), valid + " ", strings.Repeat("x", 300)} {
		if _, err := New(Config{PasswordHash: hash}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid hash configuration accepted")
		}
	}
	if _, err := New(Config{PasswordHash: valid, TTL: 2 * time.Hour}); err == nil {
		t.Fatal("unbounded TTL accepted")
	}
}
func TestLoginLookupExpiryLogoutAndSecretRedaction(t *testing.T) {
	now := time.Now()
	m := manager(t, func() time.Time { return now })
	session, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	if len(session.Token) != 64 || len(session.CSRFToken) != 64 || session.Token == session.CSRFToken {
		t.Fatal("invalid session entropy shape")
	}
	stored, err := m.Lookup(session.Token)
	if err != nil || stored.Token != "" || stored.ID != session.ID {
		t.Fatal("session lookup retained token or lost identity")
	}
	encoded, _ := json.Marshal(session)
	if strings.Contains(string(encoded), session.Token) || strings.Contains(string(encoded), session.CSRFToken) {
		t.Fatal("session JSON exposed credential")
	}
	if strings.Contains(fmt.Sprintf("%+v", session), session.Token) || strings.Contains(fmt.Sprintf("%#v", Config{PasswordHash: fixtureHash()}), fixtureHash()) {
		t.Fatal("formatter exposed secret")
	}
	m.Logout(session.Token)
	if _, err = m.Lookup(session.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("logout did not revoke")
	}
	next, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("second fixture login failed")
	}
	if next.Token == session.Token || next.CSRFToken == session.CSRFToken {
		t.Fatal("login did not rotate")
	}
	now = now.Add(DefaultTTL)
	if _, err = m.Lookup(next.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired session accepted")
	}
}
func TestCredentialFailureRateAndConcurrencyBounds(t *testing.T) {
	m := manager(t, nil)
	if _, err := m.Login(context.Background(), "127.0.0.1", "wrong-fixture-password"); !errors.Is(err, ErrCredentials) {
		t.Fatal("wrong password accepted")
	}
	for i := 0; i < 4; i++ {
		_, _ = m.Login(context.Background(), "127.0.0.1", "")
	}
	if _, err := m.Login(context.Background(), "127.0.0.1", fixturePassword); !errors.Is(err, ErrRateLimited) {
		t.Fatal("peer rate cap failed")
	}
	m.hashing <- struct{}{}
	if _, err := m.Login(context.Background(), "127.0.0.2", fixturePassword); !errors.Is(err, ErrBusy) {
		t.Fatal("hash concurrency cap failed")
	}
	<-m.hashing
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Login(ctx, "127.0.0.3", fixturePassword); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled login proceeded")
	}
}
func TestSessionAndPeerMapsAreBounded(t *testing.T) {
	m := manager(t, nil)
	now := m.Now()
	for i := 0; i < 32; i++ {
		key := [32]byte{byte(i)}
		m.sessions[key] = Session{ExpiresAt: now.Add(time.Hour)}
	}
	if _, err := m.Login(context.Background(), "127.0.0.1", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("session cap failed")
	}
	for i := 0; i < 30; i++ {
		_ = m.attempt(fmt.Sprintf("10.0.0.%d", i+1))
	}
	if err := m.attempt("10.0.1.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("global rate cap failed")
	}
}

func TestManagerValueAndPointerFormattingAndCopies(t *testing.T) {
	m := manager(t, nil)
	session, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	for _, value := range []any{m, *m} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			text := fmt.Sprintf(format, value)
			if text != "operatorauth.Manager{secrets:redacted}" || strings.Contains(text, session.CSRFToken) {
				t.Fatal("manager diagnostics exposed state")
			}
		}
	}
	copy := *m
	copy.Logout(session.Token)
	if _, err = m.Lookup(session.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("manager copy lost shared revocation state")
	}
}

func TestLogoutLinearizesAfterAdmittedMutation(t *testing.T) {
	m := manager(t, nil)
	session, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	release, err := session.BeginMutation(context.Background())
	if err != nil {
		t.Fatal("valid lease denied")
	}
	done := make(chan struct{})
	go func() { m.Logout(session.Token); close(done) }()
	select {
	case <-session.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not revoke")
	}
	select {
	case <-done:
		t.Fatal("logout returned before admitted mutation finished")
	default:
	}
	if _, err := session.BeginMutation(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("new work admitted after revocation")
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not complete after mutation release")
	}
	if _, err := m.Lookup(session.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("session remained active")
	}
}
func TestExpiryRejectsAdmissionAndCannotReactivateOnClockRollback(t *testing.T) {
	now := time.Now()
	m := manager(t, func() time.Time { return now })
	session, err := m.Login(context.Background(), "127.0.0.1", fixturePassword)
	if err != nil {
		t.Fatal("fixture login failed")
	}
	now = now.Add(DefaultTTL)
	if _, err := session.BeginMutation(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired work admitted")
	}
	_, _ = m.Lookup(session.Token)
	now = now.Add(-DefaultTTL)
	if _, err := session.BeginMutation(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("purged session reactivated")
	}
}
