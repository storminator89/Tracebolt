package alarmdelivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SettingsFile = "alarm-settings.json"
const settingsFileSchema = "tracebolt.alarm-settings-config.v1"
const TestSchemaVersion = "tracebolt.alarm-test.v1"
const TestRule = "delivery-test"

var ErrSettingsConflict = errors.New("alarm_settings_changed")
var ErrSettingsBusy = errors.New("alarm_settings_busy")
var ErrSettingsUnavailable = errors.New("alarm_settings_unavailable")
var ErrTestLimited = errors.New("alarm_test_limited")

type TestStatus struct {
	EventID   string    `json:"eventId"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"createdAt"`
}
type SettingsView struct {
	SchemaVersion   string      `json:"schemaVersion"`
	Mode            string      `json:"mode"`
	Revision        string      `json:"revision"`
	Configured      bool        `json:"configured"`
	Enabled         bool        `json:"enabled"`
	DestinationHost string      `json:"destinationHost"`
	Test            *TestStatus `json:"test"`
	Blocked         bool        `json:"blocked"`
}
type SettingsChange struct {
	ExpectedRevision           string `json:"expectedRevision"`
	Operation                  string `json:"operation"`
	Endpoint                   string `json:"endpoint"`
	PayloadSharingAcknowledged bool   `json:"payloadSharingAcknowledged"`
	PlaintextAcknowledged      bool   `json:"plaintextAcknowledged"`
}

func (SettingsChange) String() string               { return "alarmdelivery.SettingsChange{redacted}" }
func (SettingsChange) GoString() string             { return "alarmdelivery.SettingsChange{redacted}" }
func (SettingsChange) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type SettingsAudit struct {
	Revision string
	Actor    string
	Action   string
	At       time.Time
}

type SettingsQueue interface {
	Queue
	ConfigureAlarms(context.Context, *Binding, time.Time) error
	ConfigureAlarmsAudited(context.Context, *Binding, SettingsAudit, time.Time) error
	EnqueueAlarmTest(context.Context, Binding, string, string, time.Time) (*TestStatus, error)
	LatestAlarmTest(context.Context, Binding) (*TestStatus, error)
}

// savedSettings is private file data, never returned by the API or formatted.
// Explicit approval is retained with the secret so a crash cannot erase the
// provenance of an enabled configuration before its outbox transaction commits.
type savedSettings struct {
	SchemaVersion string    `json:"schemaVersion"`
	Revision      string    `json:"revision"`
	ManagerID     string    `json:"managerInstanceId"`
	Profile       string    `json:"profile"`
	Configured    bool      `json:"configured"`
	Enabled       bool      `json:"enabled"`
	Endpoint      string    `json:"endpoint"`
	Generation    string    `json:"generation"`
	ApprovedBy    string    `json:"approvedBy"`
	ApprovedAt    time.Time `json:"approvedAt"`
	LastAction    string    `json:"lastAction"`
	LastActor     string    `json:"lastActor"`
	ChangedAt     time.Time `json:"changedAt"`
}

func (savedSettings) String() string   { return "alarmdelivery.savedSettings{redacted}" }
func (savedSettings) GoString() string { return "alarmdelivery.savedSettings{redacted}" }
func newRevision() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrConfiguration
	}
	return hex.EncodeToString(b[:]), nil
}
func validRevision(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func validSettingsActor(actor string) bool {
	return actor == "shared-administrator" || len(actor) == 41 && actor[:9] == "operator_" && validRevision(actor[9:]) && actor != "operator_00000000000000000000000000000000"
}
func (s savedSettings) config(managerID, profile string) (Config, error) {
	if s.SchemaVersion != settingsFileSchema || !validRevision(s.Revision) || s.ManagerID != managerID || s.Profile != profile || !identifier.MatchString(managerID) || profile != "tls" && profile != "http-test" {
		return Config{}, ErrConfiguration
	}
	if s.LastAction == "" {
		if s.LastActor != "" || !s.ChangedAt.IsZero() || s.Configured {
			return Config{}, ErrConfiguration
		}
	} else if (s.LastAction != "replace" && s.LastAction != "enable" && s.LastAction != "disable") || !validSettingsActor(s.LastActor) || s.ChangedAt.IsZero() {
		return Config{}, ErrConfiguration
	}
	if !s.Configured {
		if s.Enabled || s.Endpoint != "" || s.Generation != "" || s.ApprovedBy != "" || !s.ApprovedAt.IsZero() {
			return Config{}, ErrConfiguration
		}
		return Config{}, nil
	}
	if !validRevision(s.Generation) || !validSettingsActor(s.ApprovedBy) || s.ApprovedAt.IsZero() {
		return Config{}, ErrConfiguration
	}
	if _, e := parseWebhookEndpoint(s.Endpoint); e != nil {
		return Config{}, ErrConfiguration
	}
	b := Binding{ManagerInstanceID: managerID, Profile: profile, DestinationID: "browser-webhook", Generation: s.Generation}
	b.Fingerprint = destinationFingerprint(b, s.Endpoint)
	return Config{enabled: s.Enabled, binding: b, endpoint: s.Endpoint}, nil
}

// Settings serializes configuration/test mutations against each outbound attempt.
// TryLock keeps HTTP session gates away from provider I/O. Construction, View and
// Change never resolve a destination or contact a provider.
type Settings struct {
	operation sync.Mutex
	mu        sync.RWMutex
	queue     SettingsQueue
	file      string
	saved     savedSettings
	config    Config
	worker    *Worker
	mode      string
	blocked   bool
	now       func() time.Time
	transport func(Config) (Transport, error)
}

func NewSettings(q SettingsQueue, stateDir, managerID, profile string, external Config) (*Settings, error) {
	return newSettings(q, stateDir, managerID, profile, external, time.Now, NewWebhook)
}
func newSettings(q SettingsQueue, stateDir, managerID, profile string, external Config, now func() time.Time, factory func(Config) (Transport, error)) (*Settings, error) {
	if q == nil || now == nil || factory == nil || !identifier.MatchString(managerID) || profile != "tls" && profile != "http-test" {
		return nil, ErrConfiguration
	}
	s := &Settings{queue: q, mode: "managed", now: now, transport: factory, saved: savedSettings{ManagerID: managerID, Profile: profile}}
	if external.external {
		if external.binding.Valid() && (external.binding.ManagerInstanceID != managerID || external.binding.Profile != profile) {
			return nil, ErrConfiguration
		}
		s.mode = "external"
		s.config = external
	} else {
		if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
			return nil, ErrConfiguration
		}
		s.file = filepath.Join(stateDir, SettingsFile)
		if lanstore.ValidateStateFile(s.file) != nil {
			return nil, ErrConfiguration
		}
		raw, e := lanconfig.ReadProtected(s.file, true, 16384)
		if e != nil {
			if _, statErr := os.Lstat(s.file); !os.IsNotExist(statErr) {
				return nil, ErrConfiguration
			}
			rev, e := newRevision()
			if e != nil {
				return nil, e
			}
			s.saved = savedSettings{SchemaVersion: settingsFileSchema, Revision: rev, ManagerID: managerID, Profile: profile}
			if _, e = s.saved.config(managerID, profile); e != nil {
				return nil, e
			}
			if e = s.write(s.saved, true); e != nil {
				return nil, e
			}
		} else {
			defer clear(raw)
			if lanconfig.StrictObject(raw, &s.saved, "schemaVersion", "revision", "managerInstanceId", "profile", "configured", "enabled", "endpoint", "generation", "approvedBy", "approvedAt", "lastAction", "lastActor", "changedAt") != nil {
				return nil, ErrConfiguration
			}
		}
		s.config, e = s.saved.config(managerID, profile)
		if e != nil {
			return nil, e
		}
	}
	if e := s.activate(context.Background(), s.config); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Settings) write(next savedSettings, create bool) error {
	if lanstore.ValidateStateFile(s.file) != nil {
		return ErrConfiguration
	}
	if !create {
		raw, e := lanconfig.ReadProtected(s.file, true, 16384)
		if e != nil {
			return ErrConfiguration
		}
		clear(raw)
	}
	raw, e := json.Marshal(next)
	if e != nil {
		return ErrConfiguration
	}
	defer clear(raw)
	dir := filepath.Dir(s.file)
	f, e := os.CreateTemp(dir, ".alarm-settings-")
	if e != nil {
		return ErrConfiguration
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrConfiguration
	}
	if create {
		// Link provides create-only publication; an unexpected existing file is not adopted.
		if os.Link(tmp, s.file) != nil {
			return ErrConfiguration
		}
		if os.Remove(tmp) != nil {
			return ErrConfiguration
		}
	} else if os.Rename(tmp, s.file) != nil {
		return ErrConfiguration
	}
	d, e := os.Open(dir)
	if e != nil {
		return ErrConfiguration
	}
	e = d.Sync()
	ce = d.Close()
	if e != nil || ce != nil {
		return ErrConfiguration
	}
	check, e := lanconfig.ReadProtected(s.file, true, 16384)
	defer clear(check)
	if e != nil || string(check) != string(raw) {
		return ErrConfiguration
	}
	return nil
}
func (s *Settings) activate(ctx context.Context, c Config) error {
	var b *Binding
	var w *Worker
	if c.Enabled() {
		binding := c.Binding()
		b = &binding
		t, e := s.transport(c)
		if e != nil {
			return e
		}
		w, e = NewWorker(s.queue, binding, t, s.now)
		if e != nil {
			return e
		}
	}
	var e error
	if s.mode != "managed" || s.saved.LastAction == "" {
		e = s.queue.ConfigureAlarms(ctx, b, s.now().UTC())
	} else {
		e = s.queue.ConfigureAlarmsAudited(ctx, b, SettingsAudit{Revision: s.saved.Revision, Actor: s.saved.LastActor, Action: s.saved.LastAction, At: s.saved.ChangedAt}, s.now().UTC())
	}
	if e != nil {
		return e
	}
	s.worker = w
	return nil
}
func (s *Settings) View(ctx context.Context) (SettingsView, error) {
	if s == nil {
		return SettingsView{SchemaVersion: "tracebolt.alarm-settings.v1", Mode: "unavailable"}, nil
	}
	s.mu.RLock()
	v := SettingsView{SchemaVersion: "tracebolt.alarm-settings.v1", Mode: s.mode, Revision: s.saved.Revision, Configured: s.config.binding.Valid(), Enabled: s.config.enabled && !s.blocked, Blocked: s.blocked}
	c := s.config
	s.mu.RUnlock()
	if v.Configured {
		u, e := parseWebhookEndpoint(c.endpoint)
		if e != nil {
			return SettingsView{}, ErrConfiguration
		}
		v.DestinationHost = u.Hostname()
		test, e := s.queue.LatestAlarmTest(ctx, c.Binding())
		if e != nil {
			return SettingsView{}, ErrSettingsUnavailable
		}
		v.Test = test
	}
	return v, nil
}
func (s *Settings) Change(ctx context.Context, in SettingsChange, actor string) error {
	if s == nil || !validSettingsActor(actor) {
		return ErrSettingsUnavailable
	}
	if !s.operation.TryLock() {
		return ErrSettingsBusy
	}
	defer s.operation.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != "managed" || s.blocked {
		return ErrSettingsUnavailable
	}
	if in.ExpectedRevision != s.saved.Revision {
		return ErrSettingsConflict
	}
	next := s.saved
	switch in.Operation {
	case "replace":
		if !in.PayloadSharingAcknowledged || next.Profile == "http-test" && !in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		if _, e := parseWebhookEndpoint(in.Endpoint); e != nil {
			return ErrConfiguration
		}
		generation, e := newRevision()
		if e != nil {
			return e
		}
		next.Configured = true
		next.Enabled = true
		next.Endpoint = in.Endpoint
		next.Generation = generation
		next.ApprovedBy = actor
		next.ApprovedAt = s.now().UTC()
	case "enable":
		if in.Endpoint != "" || !next.Configured || !in.PayloadSharingAcknowledged || next.Profile == "http-test" && !in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		// Every enable is a new destination generation. A disabled or changed old
		// opening cannot acquire an unpaired recovery after re-enabling.
		generation, e := newRevision()
		if e != nil {
			return e
		}
		next.Generation = generation
		next.Enabled = true
		next.ApprovedBy = actor
		next.ApprovedAt = s.now().UTC()
	case "disable":
		if in.Endpoint != "" || in.PayloadSharingAcknowledged || in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		next.Enabled = false
	default:
		return ErrConfiguration
	}
	revision, e := newRevision()
	if e != nil {
		return e
	}
	next.Revision = revision
	next.LastAction = in.Operation
	next.LastActor = actor
	next.ChangedAt = s.now().UTC()
	c, e := next.config(next.ManagerID, next.Profile)
	if e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Persist before activating: on crash startup reconciles this exact file with
	// the outbox before any worker runs. A failure after publication is uncertain,
	// stops the worker, and requires restart/readback; never silently rolls back.
	if e = s.write(next, false); e != nil {
		s.block(ctx)
		return ErrSettingsUnavailable
	}
	s.saved = next
	s.config = c
	if e = s.activate(ctx, c); e != nil {
		s.block(ctx)
		return ErrSettingsUnavailable
	}
	return nil
}
func (s *Settings) Test(ctx context.Context, revision, requestID, actor string) error {
	if s == nil {
		return ErrSettingsUnavailable
	}
	if !validSettingsActor(actor) || !validRevision(requestID) {
		return ErrConfiguration
	}
	if !s.operation.TryLock() {
		return ErrSettingsBusy
	}
	defer s.operation.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mode != "managed" || s.blocked || !s.config.enabled {
		return ErrSettingsUnavailable
	}
	if revision != s.saved.Revision {
		return ErrSettingsConflict
	}
	_, e := s.queue.EnqueueAlarmTest(ctx, s.config.Binding(), requestID, actor, s.now().UTC())
	return e
}
func (s *Settings) Step(ctx context.Context) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	if s.worker == nil {
		return nil
	}
	return s.worker.Step(ctx)
}
func (s *Settings) Run(ctx context.Context, warn func()) error {
	var last time.Time
	for {
		e := s.Step(ctx)
		if ctx.Err() != nil {
			return nil
		}
		now := s.now()
		if e != nil && warn != nil && (last.IsZero() || now.Sub(last) >= time.Minute) {
			warn()
			last = now
		}
		// Start the interval after completion, not before it. Even a slow
		// provider/backlog leaves a real idle window for Disable or replacement.
		timer := time.NewTimer(SendInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (s *Settings) Matches(managerID, profile string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saved.ManagerID == managerID && s.saved.Profile == profile
}

// block is called only while both operation and mu are held. It stops local
// dispatch before bounded best-effort suppression, even if the request expired.
// This is an emergency stop, never a fabricated operator-approved disable.
func (s *Settings) block(ctx context.Context) {
	s.worker = nil
	s.blocked = true
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = s.queue.ConfigureAlarms(cleanup, nil, s.now().UTC())
}
func (s *Settings) DeliveryEnabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.enabled && !s.blocked
}
