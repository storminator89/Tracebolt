package operatorauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"testing"
	"time"
)

const namedID = "operator_0123456789abcdef0123456789abcdef"

func namedConfig() Config {
	return Config{Operators: []Operator{{ID: namedID, Username: "reader", PasswordHash: fixtureHash(), Capabilities: []Capability{Read, RestartService}}}}
}
func namedManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(namedConfig())
	if err != nil {
		t.Fatal("valid named fixture rejected")
	}
	return m
}
func namedLogin(t *testing.T, m *Manager) Session {
	t.Helper()
	s, err := m.LoginNamed(context.Background(), "127.0.0.1", "reader", fixturePassword)
	if err != nil {
		t.Fatal("named fixture login rejected")
	}
	return s
}

func TestNamedConfigurationFailClosed(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"mixed modes":     func(c *Config) { c.PasswordHash = fixtureHash() },
		"empty operators": func(c *Config) { c.Operators = []Operator{} },
		"duplicate id":    func(c *Config) { o := c.Operators[0]; o.Username = "other"; c.Operators = append(c.Operators, o) },
		"duplicate username": func(c *Config) {
			o := c.Operators[0]
			o.ID = "operator_11111111111111111111111111111111"
			c.Operators = append(c.Operators, o)
		},
		"unknown capability":   func(c *Config) { c.Operators[0].Capabilities = append(c.Operators[0].Capabilities, "admin") },
		"duplicate capability": func(c *Config) { c.Operators[0].Capabilities = append(c.Operators[0].Capabilities, Read) },
		"missing read":         func(c *Config) { c.Operators[0].Capabilities = []Capability{RestartService} },
		"empty grants":         func(c *Config) { c.Operators[0].Capabilities = nil },
		"unbounded operators":  func(c *Config) { c.Operators = make([]Operator, MaxOperators+1) },
		"invalid id":           func(c *Config) { c.Operators[0].ID = "operator_reader" },
		"uppercase username":   func(c *Config) { c.Operators[0].Username = "Reader" },
		"trimmed username":     func(c *Config) { c.Operators[0].Username = " reader" },
		"empty username":       func(c *Config) { c.Operators[0].Username = "" },
		"long username":        func(c *Config) { c.Operators[0].Username = strings.Repeat("r", 65) },
		"bad hash":             func(c *Config) { c.Operators[0].PasswordHash = "not-a-hash" },
		"unequal work factors": func(c *Config) {
			o := c.Operators[0]
			o.ID = "operator_11111111111111111111111111111111"
			o.Username = "other"
			o.PasswordHash = strings.Replace(o.PasswordHash, "t=2", "t=3", 1)
			c.Operators = append(c.Operators, o)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := namedConfig()
			mutate(&c)
			if _, err := New(c); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid named authority accepted")
			}
		})
	}
}

func TestNamedLoginIdentityCapabilitiesAndDefensiveCopies(t *testing.T) {
	c := namedConfig()
	m, err := New(c)
	if err != nil {
		t.Fatal("fixture configuration failed")
	}
	c.Operators[0].ID = "operator_11111111111111111111111111111111"
	c.Operators[0].Capabilities[0] = ExecuteUpdates
	c.Operators[0].Username = "modified"
	s := namedLogin(t, m)
	if !m.Named() || !s.Named() || s.ActorID() != namedID {
		t.Fatal("server identity was not preserved")
	}
	capabilities := s.Capabilities()
	if len(capabilities) != 2 || capabilities[0] != Read || capabilities[1] != RestartService {
		t.Fatal("explicit grants changed")
	}
	capabilities[0] = ExecuteUpdates
	for _, cap := range []Capability{Read, RestartService} {
		release, err := s.BeginCapability(context.Background(), cap)
		if err != nil {
			t.Fatal("explicit grant denied")
		}
		release()
		release()
	}
	for _, cap := range []Capability{ExecuteUpdates, PlanUpdates, "admin", ""} {
		if _, err := s.BeginCapability(context.Background(), cap); !errors.Is(err, ErrForbidden) {
			t.Fatal("ungranted capability admitted")
		}
	}
	stored, err := m.Lookup(s.Token)
	if err != nil || stored.ActorID() != namedID || stored.Token != "" {
		t.Fatal("lookup lost server authority or retained token")
	}
	for _, value := range []any{namedConfig(), namedConfig().Operators[0], s, m} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), fixtureHash()) || strings.Contains(fmt.Sprintf(format, value), s.Token) {
				t.Fatal("named auth diagnostics exposed secret")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), fixtureHash()) || strings.Contains(string(raw), s.Token) {
			t.Fatal("named auth JSON exposed secret")
		}
	}
}

func TestNamedUnknownUserAndWrongModeCannotFallback(t *testing.T) {
	m := namedManager(t)
	for i, username := range []string{"unknown", "Reader", " reader", ""} {
		if _, err := m.LoginNamed(context.Background(), fmt.Sprintf("127.0.0.%d", i+1), username, fixturePassword); !errors.Is(err, ErrCredentials) {
			t.Fatal("unknown username accepted the dummy verifier password")
		}
	}
	if _, err := m.Login(context.Background(), "127.0.0.5", fixturePassword); !errors.Is(err, ErrCredentials) {
		t.Fatal("named mode fell back to shared login")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.6", "reader", "wrong-password-fixture"); !errors.Is(err, ErrCredentials) {
		t.Fatal("wrong named password accepted")
	}
	legacy := manager(t, nil)
	if _, err := legacy.LoginNamed(context.Background(), "127.0.0.1", "reader", fixturePassword); !errors.Is(err, ErrCredentials) {
		t.Fatal("shared mode granted named identity")
	}
	s, err := legacy.Login(context.Background(), "127.0.0.2", fixturePassword)
	if err != nil || s.Named() || s.ActorID() != "" || len(s.Capabilities()) != 1 || s.Capabilities()[0] != Read {
		t.Fatal("legacy login compatibility changed")
	}
	for _, cap := range []Capability{PlanUpdates, ExecuteUpdates, RestartService} {
		if _, err := s.BeginCapability(context.Background(), cap); !errors.Is(err, ErrForbidden) {
			t.Fatal("legacy session gained maintenance authority")
		}
	}
}

func TestNamedUnknownUsersShareHashConcurrencyAndRateLimits(t *testing.T) {
	m := namedManager(t)
	m.hashing <- struct{}{}
	for _, username := range []string{"reader", "unknown"} {
		if _, err := m.LoginNamed(context.Background(), "127.0.0.1", username, fixturePassword); !errors.Is(err, ErrBusy) {
			t.Fatal("unknown user bypassed bounded hash work")
		}
	}
	<-m.hashing
	for i := 0; i < 3; i++ {
		_, _ = m.LoginNamed(context.Background(), "127.0.0.1", "unknown", "")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "reader", fixturePassword); !errors.Is(err, ErrRateLimited) {
		t.Fatal("unknown attempts bypassed shared peer budget")
	}
}

func TestNamedCapabilityRevocationWaitsForAdmittedWork(t *testing.T) {
	m := namedManager(t)
	s := namedLogin(t, m)
	release, err := s.BeginCapability(context.Background(), RestartService)
	if err != nil {
		t.Fatal("fixture capability admission failed")
	}
	done := make(chan struct{})
	go func() { m.Logout(s.Token); close(done) }()
	select {
	case <-s.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not revoke named session")
	}
	if _, err := s.BeginCapability(context.Background(), RestartService); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked capability readmitted")
	}
	select {
	case <-done:
		t.Fatal("logout returned before admitted work drained")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("named revocation did not finish")
	}
}

func TestNamedExpiryAndRestartInvalidateAuthority(t *testing.T) {
	now := time.Now()
	c := namedConfig()
	c.Now = func() time.Time { return now }
	m, err := New(c)
	if err != nil {
		t.Fatal("fixture config failed")
	}
	s := namedLogin(t, m)
	now = now.Add(DefaultTTL)
	if _, err := s.BeginCapability(context.Background(), RestartService); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired capability admitted")
	}
	// Static config changes take effect only at restart. No session token is
	// portable into a restarted manager, even with unchanged credentials.
	restarted := namedManager(t)
	if _, err := restarted.Lookup(s.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("session survived manager restart")
	}
	c = namedConfig()
	c.Operators[0].Capabilities = []Capability{Read}
	changed, _ := New(c)
	fresh := namedLogin(t, changed)
	if _, err := fresh.BeginCapability(context.Background(), RestartService); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed capability survived static restart")
	}
	c.Operators[0].Username = "replacement"
	removed, _ := New(c)
	if _, err := removed.LoginNamed(context.Background(), "127.0.0.1", "reader", fixturePassword); !errors.Is(err, ErrCredentials) {
		t.Fatal("removed operator survived static restart")
	}
	if _, err := (Session{}).BeginCapability(context.Background(), RestartService); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("fabricated session acquired capability")
	}
}

func TestNamedAccountsDoNotSharePasswordsIdentityOrCapabilities(t *testing.T) {
	const otherPassword = "another-synthetic-password-only"
	salt := []byte("other-fixture-salt")
	hash := argon2.IDKey([]byte(otherPassword), salt, 2, 65536, 1, 32)
	otherHash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	c := namedConfig()
	const otherID = "operator_11111111111111111111111111111111"
	c.Operators = append(c.Operators, Operator{ID: otherID, Username: "planner", PasswordHash: otherHash, Capabilities: []Capability{Read, PlanUpdates}})
	m, err := New(c)
	if err != nil {
		t.Fatal("multi-account fixture rejected")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "reader", otherPassword); !errors.Is(err, ErrCredentials) {
		t.Fatal("another account password authenticated reader")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "planner", fixturePassword); !errors.Is(err, ErrCredentials) {
		t.Fatal("another account password authenticated planner")
	}
	reader := namedLogin(t, m)
	planner, err := m.LoginNamed(context.Background(), "127.0.0.1", "planner", otherPassword)
	if err != nil || planner.ActorID() != otherID || reader.ActorID() != namedID {
		t.Fatal("account identity crossed")
	}
	if _, err := planner.BeginCapability(context.Background(), RestartService); !errors.Is(err, ErrForbidden) {
		t.Fatal("planner inherited another account grant")
	}
	if _, err := reader.BeginCapability(context.Background(), PlanUpdates); !errors.Is(err, ErrForbidden) {
		t.Fatal("reader inherited another account grant")
	}
	release, err := planner.BeginCapability(context.Background(), PlanUpdates)
	if err != nil {
		t.Fatal("explicit planning grant denied")
	}
	release()
	m.Logout(reader.Token)
	if _, err := m.Lookup(planner.Token); err != nil {
		t.Fatal("one session logout revoked another account")
	}
}

func TestApplicationCheckCapabilityIsExplicitAndSessionBound(t *testing.T) {
	c := namedConfig()
	c.Operators[0].Capabilities = []Capability{Read, PlanUpdates, ExecuteUpdates, RestartService, ManageAlarms}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	s := namedLogin(t, m)
	if _, err := s.BeginCapability(context.Background(), ManageApplicationChecks); !errors.Is(err, ErrForbidden) {
		t.Fatal("existing grants imply application administration")
	}
	c.Operators[0].Capabilities = append(c.Operators[0].Capabilities, ManageApplicationChecks)
	m, err = New(c)
	if err != nil {
		t.Fatal("explicit application grant rejected", err)
	}
	s = namedLogin(t, m)
	caps := s.Capabilities()
	if len(caps) != 6 || caps[5] != ManageApplicationChecks {
		t.Fatal("display omitted explicit application grant")
	}
	raw, _ := json.Marshal(caps)
	if !strings.Contains(string(raw), `"manage_application_checks"`) {
		t.Fatal("wire grant lost")
	}
	release, err := s.BeginCapability(context.Background(), ManageApplicationChecks)
	if err != nil {
		t.Fatal("explicit grant denied")
	}
	release()
	m.Logout(s.Token)
	if _, err := s.BeginCapability(context.Background(), ManageApplicationChecks); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked application grant reused")
	}
	c.Operators[0].Capabilities = append(c.Operators[0].Capabilities, ManageApplicationChecks)
	if _, err := New(c); !errors.Is(err, ErrConfiguration) {
		t.Fatal("duplicate application grant accepted")
	}
	c.Operators[0].Capabilities = []Capability{ManageApplicationChecks}
	if _, err := New(c); !errors.Is(err, ErrConfiguration) {
		t.Fatal("application grant implied read")
	}
}
