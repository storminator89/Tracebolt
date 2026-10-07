package applicationcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const SettingsFile = "application-check-settings.json"
const SettingsSchemaVersion = "tracebolt.application-check-settings.v1"
const settingsFileSchema = "tracebolt.application-check-settings-state.v1"
const settingsFileLimit = 65536
const settingsAuditLimit = 32

var ErrSettingsConflict = errors.New("application_check_settings_changed")
var ErrSettingsBusy = errors.New("application_check_settings_busy")
var ErrSettingsUnavailable = errors.New("application_check_settings_unavailable")

// SettingsView is privileged configuration review data, separate from the
// destination-free retained-status View. Each target is an exact v2 kind object.
type SettingsView struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Mode            string            `json:"mode"`
	Revision        string            `json:"revision"`
	Configured      bool              `json:"configured"`
	Enabled         bool              `json:"enabled"`
	Blocked         bool              `json:"blocked"`
	IntervalSeconds int               `json:"intervalSeconds"`
	Targets         []json.RawMessage `json:"targets"`
}

type SettingsChange struct {
	ExpectedRevision              string            `json:"expectedRevision"`
	Operation                     string            `json:"operation"`
	IntervalSeconds               int               `json:"intervalSeconds"`
	Targets                       []json.RawMessage `json:"targets"`
	ChecksFromManagerAcknowledged bool              `json:"checksFromManagerAcknowledged"`
	DestinationsAcknowledged      bool              `json:"destinationsAcknowledged"`
	PlaintextAcknowledged         bool              `json:"plaintextAcknowledged"`
}

func (SettingsView) String() string                 { return "applicationcheck.SettingsView{redacted}" }
func (SettingsView) GoString() string               { return "applicationcheck.SettingsView{redacted}" }
func (SettingsChange) String() string               { return "applicationcheck.SettingsChange{redacted}" }
func (SettingsChange) GoString() string             { return "applicationcheck.SettingsChange{redacted}" }
func (SettingsChange) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Settings) String() string                    { return "applicationcheck.Settings{redacted}" }
func (*Settings) GoString() string                  { return "applicationcheck.Settings{redacted}" }
func (*Settings) MarshalJSON() ([]byte, error)      { return []byte(`{"redacted":true}`), nil }

// Approval and audit are committed in the same atomic envelope as the draft.
// Audit contains only bounded operator identifiers and operation metadata.
type settingsAudit struct {
	Actor      string    `json:"actor"`
	Operation  string    `json:"operation"`
	Revision   string    `json:"revision"`
	Generation string    `json:"generation"`
	Timestamp  time.Time `json:"timestamp"`
}
type savedSettings struct {
	SchemaVersion   string            `json:"schemaVersion"`
	ManagerID       string            `json:"managerInstanceId"`
	Origin          string            `json:"operatorOrigin"`
	Profile         string            `json:"profile"`
	Revision        string            `json:"revision"`
	Generation      string            `json:"generation"`
	Configured      bool              `json:"configured"`
	Enabled         bool              `json:"enabled"`
	IntervalSeconds int               `json:"intervalSeconds"`
	Targets         []json.RawMessage `json:"targets"`
	Audit           []settingsAudit   `json:"audit"`
}

func (savedSettings) String() string   { return "applicationcheck.savedSettings{redacted}" }
func (savedSettings) GoString() string { return "applicationcheck.savedSettings{redacted}" }

// Settings owns one supervisor lifecycle. operation serializes mutations and
// worker replacement; mu protects inert readers. A mutation first cancels and
// joins the old monitor, then commits the entire configuration/audit envelope.
// Only Run can start a monitor. A failed/uncertain write or interrupted mutation
// blocks this instance until restart and verified protected-file readback.
type Settings struct {
	mutation    sync.Mutex // admission rejects concurrent changes, not brief supervisor work
	operation   sync.Mutex
	mu          sync.RWMutex
	running     atomic.Bool
	file        string
	digest      [32]byte
	saved       savedSettings
	config      Config
	mode        string
	blocked     bool
	monitor     *Monitor
	wake        chan struct{}
	cancel      context.CancelFunc // operation protects worker lifecycle fields
	done        chan struct{}
	now         func() time.Time
	wait        func(context.Context, time.Duration) bool
	nextAllowed time.Time // mu protects the cooldown across configuration generations
	factory     func(Config) *Monitor
	persist     func(savedSettings, bool) error
}

func NewSettings(stateDir, managerID, origin, profile string, external Config) (*Settings, error) {
	return newSettings(stateDir, managerID, origin, profile, external, time.Now, New)
}

func newSettings(stateDir, managerID, origin, profile string, external Config, now func() time.Time, factory func(Config) *Monitor) (*Settings, error) {
	if !validSettingsBinding(managerID, origin, profile) || now == nil || factory == nil {
		return nil, ErrConfiguration
	}
	s := &Settings{mode: "managed", now: now, wait: wait, factory: factory, wake: make(chan struct{}, 1), saved: savedSettings{ManagerID: managerID, Origin: origin, Profile: profile}}
	s.persist = s.write
	if external.external {
		if !external.Matches(managerID, origin, profile) {
			return nil, ErrConfiguration
		}
		s.mode, s.config = "external", external
	} else {
		if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
			return nil, ErrConfiguration
		}
		s.file = filepath.Join(stateDir, SettingsFile)
		if lanstore.ValidateStateFile(s.file) != nil {
			return nil, ErrConfiguration
		}
		raw, err := lanconfig.ReadProtected(s.file, true, settingsFileLimit)
		if err != nil {
			if _, statErr := os.Lstat(s.file); !os.IsNotExist(statErr) {
				return nil, ErrConfiguration
			}
			revision, err := newSettingsRevision()
			if err != nil {
				return nil, err
			}
			generation, err := newSettingsRevision()
			if err != nil {
				return nil, err
			}
			s.saved = savedSettings{SchemaVersion: settingsFileSchema, ManagerID: managerID, Origin: origin, Profile: profile, Revision: revision, Generation: generation, IntervalSeconds: 60, Targets: []json.RawMessage{}, Audit: []settingsAudit{}}
			if err = s.write(s.saved, true); err != nil {
				return nil, err
			}
		} else {
			defer clear(raw)
			s.saved, err = parseSavedSettings(raw)
			if err != nil {
				return nil, err
			}
			s.digest = sha256.Sum256(raw)
		}
		s.config, err = s.saved.config(managerID, origin, profile)
		if err != nil {
			return nil, err
		}
	}
	s.monitor = s.newMonitor(s.config)
	if s.monitor == nil {
		return nil, ErrConfiguration
	}
	return s, nil
}

func validSettingsBinding(id, origin, profile string) bool {
	if len(id) > 80 || origin == "" || len(origin) > 2048 || profile != lanconfig.TLS && profile != lanconfig.HTTPTest {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true // Empty manager ID is the existing manual-manager binding.
}
func newSettingsRevision() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrConfiguration
	}
	return hex.EncodeToString(b[:]), nil
}
func validSettingsRevision(s string) bool {
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
	return actor == "shared-administrator" || len(actor) == 41 && actor[:9] == "operator_" && validSettingsRevision(actor[9:]) && actor != "operator_00000000000000000000000000000000"
}

func parseSavedSettings(raw []byte) (savedSettings, error) {
	f, err := object(raw, "schemaVersion", "managerInstanceId", "operatorOrigin", "profile", "revision", "generation", "configured", "enabled", "intervalSeconds", "targets", "audit")
	var s savedSettings
	var audit []json.RawMessage
	if err != nil || len(f) != 11 || !decode(f, "schemaVersion", &s.SchemaVersion) || !decode(f, "managerInstanceId", &s.ManagerID) || !decode(f, "operatorOrigin", &s.Origin) || !decode(f, "profile", &s.Profile) || !decode(f, "revision", &s.Revision) || !decode(f, "generation", &s.Generation) || !decode(f, "configured", &s.Configured) || !decode(f, "enabled", &s.Enabled) || !decode(f, "intervalSeconds", &s.IntervalSeconds) || !decode(f, "targets", &s.Targets) || !decode(f, "audit", &audit) || len(audit) > settingsAuditLimit {
		return savedSettings{}, ErrConfiguration
	}
	s.Audit = []settingsAudit{}
	for _, rawEvent := range audit {
		f, err := object(rawEvent, "actor", "operation", "revision", "generation", "timestamp")
		var event settingsAudit
		if err != nil || len(f) != 5 || !decode(f, "actor", &event.Actor) || !decode(f, "operation", &event.Operation) || !decode(f, "revision", &event.Revision) || !decode(f, "generation", &event.Generation) || !decode(f, "timestamp", &event.Timestamp) {
			return savedSettings{}, ErrConfiguration
		}
		s.Audit = append(s.Audit, event)
	}
	return s, nil
}

func draftConfig(interval int, rawTargets []json.RawMessage, managerID, origin, profile string) (Config, error) {
	if interval < 60 || interval > 3600 || len(rawTargets) < 1 || len(rawTargets) > MaxTargets {
		return Config{}, ErrConfiguration
	}
	c := Config{schema: ConfigSchemaVersionV2, managerID: managerID, origin: origin, profile: profile, interval: time.Duration(interval) * time.Second}
	seen := map[string]bool{}
	size := 0
	for _, raw := range rawTargets {
		size += len(raw)
		if size > 32768 {
			return Config{}, ErrConfiguration
		}
		t, err := parseTarget(raw, ConfigSchemaVersionV2, profile)
		if err != nil || seen[t.ID] {
			return Config{}, ErrConfiguration
		}
		seen[t.ID] = true
		c.targets = append(c.targets, t)
	}
	return c, nil
}

func (s savedSettings) config(managerID, origin, profile string) (Config, error) {
	if s.SchemaVersion != settingsFileSchema || !validSettingsBinding(managerID, origin, profile) || s.ManagerID != managerID || s.Origin != origin || s.Profile != profile || !validSettingsRevision(s.Revision) || !validSettingsRevision(s.Generation) || s.Revision == s.Generation || s.Targets == nil || s.Audit == nil || len(s.Audit) > settingsAuditLimit {
		return Config{}, ErrConfiguration
	}
	seen := map[string]bool{}
	for _, event := range s.Audit {
		if !validSettingsActor(event.Actor) || !validSettingsRevision(event.Revision) || !validSettingsRevision(event.Generation) || event.Revision == event.Generation || event.Timestamp.IsZero() || event.Operation != "save" && event.Operation != "enable" && event.Operation != "disable" || seen[event.Revision] || seen[event.Generation] {
			return Config{}, ErrConfiguration
		}
		seen[event.Revision], seen[event.Generation] = true, true
	}
	if len(s.Audit) == 0 {
		if s.Configured || s.Enabled {
			return Config{}, ErrConfiguration
		}
	} else {
		last := s.Audit[len(s.Audit)-1]
		if last.Revision != s.Revision || last.Generation != s.Generation || s.Enabled != (last.Operation == "enable") || last.Operation == "save" && !s.Configured {
			return Config{}, ErrConfiguration
		}
	}
	if !s.Configured {
		if s.Enabled || s.IntervalSeconds != 60 || len(s.Targets) != 0 {
			return Config{}, ErrConfiguration
		}
		return Config{schema: ConfigSchemaVersionV2}, nil
	}
	c, err := draftConfig(s.IntervalSeconds, s.Targets, managerID, origin, profile)
	c.enabled = s.Enabled
	return c, err
}

func targetJSON(t target) json.RawMessage {
	kind := t.Kind
	if kind == "" {
		kind = kindHTTP
	}
	fields := map[string]any{"kind": kind, "id": t.ID, "allowedAddresses": append([]string{}, t.AllowedAddresses...), "allowPrivateLAN": t.AllowPrivateLAN}
	switch kind {
	case kindHTTP:
		fields["url"], fields["plaintextHTTPAcknowledged"] = t.URL, t.PlaintextHTTPAcknowledged
	case kindDNS:
		fields["host"] = t.Host
	case kindTCP:
		fields["host"], fields["port"] = t.Host, t.Port
	}
	raw, _ := json.Marshal(fields)
	return raw
}
func targetsJSON(c Config) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(c.targets))
	for _, t := range c.targets {
		out = append(out, targetJSON(t))
	}
	return out
}

func (s *Settings) Matches(managerID, origin, profile string) bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saved.ManagerID == managerID && s.saved.Origin == origin && s.saved.Profile == profile
}
func (s *Settings) View() SettingsView {
	v := SettingsView{SchemaVersion: SettingsSchemaVersion, Mode: "unavailable", IntervalSeconds: 60, Targets: []json.RawMessage{}}
	if s == nil {
		return v
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v.Mode, v.Revision, v.Blocked = s.mode, s.saved.Revision, s.blocked
	v.Configured, v.Enabled = len(s.config.targets) > 0, s.config.enabled && !s.blocked
	if s.config.interval != 0 {
		v.IntervalSeconds = int(s.config.interval / time.Second)
	}
	v.Targets = targetsJSON(s.config)
	return v
}
func (s *Settings) Status() View {
	if s == nil {
		return (*Monitor)(nil).Status()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.blocked {
		return New(Config{schema: s.config.schema}).Status()
	}
	return s.monitor.Status()
}

func (s *Settings) Change(ctx context.Context, in SettingsChange, actor string) error {
	if s == nil {
		return ErrSettingsUnavailable
	}
	if !validSettingsActor(actor) {
		return ErrConfiguration
	}
	if !s.mutation.TryLock() {
		return ErrSettingsBusy
	}
	defer s.mutation.Unlock()
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.RLock()
	next, unavailable := s.saved, s.mode != "managed" || s.blocked
	s.mu.RUnlock()
	if unavailable {
		return ErrSettingsUnavailable
	}
	if !validSettingsRevision(in.ExpectedRevision) || in.ExpectedRevision != next.Revision {
		return ErrSettingsConflict
	}
	switch in.Operation {
	case "save":
		if in.ChecksFromManagerAcknowledged || in.DestinationsAcknowledged || in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		c, err := draftConfig(in.IntervalSeconds, in.Targets, next.ManagerID, next.Origin, next.Profile)
		if err != nil {
			return err
		}
		next.Configured, next.Enabled, next.IntervalSeconds, next.Targets = true, false, in.IntervalSeconds, targetsJSON(c)
	case "enable":
		if in.IntervalSeconds != 0 || in.Targets != nil || !next.Configured || !in.ChecksFromManagerAcknowledged || !in.DestinationsAcknowledged || next.Profile == lanconfig.HTTPTest && !in.PlaintextAcknowledged || next.Profile != lanconfig.HTTPTest && in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		next.Enabled = true
	case "disable":
		if in.IntervalSeconds != 0 || in.Targets != nil || in.ChecksFromManagerAcknowledged || in.DestinationsAcknowledged || in.PlaintextAcknowledged {
			return ErrConfiguration
		}
		next.Enabled = false
	default:
		return ErrConfiguration
	}
	var err error
	next.Revision, err = newSettingsRevision()
	if err != nil {
		return err
	}
	next.Generation, err = newSettingsRevision()
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if now.IsZero() {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.block()
		return ErrSettingsUnavailable
	}
	// Record the actual wall clock. Array order and revision/generation identity
	// establish event order even after a clock correction; a backward clock must
	// never prevent an admitted Disable from stopping the worker.
	next.Audit = append(append([]settingsAudit{}, next.Audit...), settingsAudit{Actor: actor, Operation: in.Operation, Revision: next.Revision, Generation: next.Generation, Timestamp: now})
	if len(next.Audit) > settingsAuditLimit {
		next.Audit = next.Audit[len(next.Audit)-settingsAuditLimit:]
	}
	c, err := next.config(next.ManagerID, next.Origin, next.Profile)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Old results cannot cross the generation boundary: stop/join before any
	// publication, then replace the entire monitor instead of reusing its rows.
	s.stopWorker()
	if err = ctx.Err(); err != nil {
		s.block()
		return err
	}
	if err = s.persist(next, false); err != nil {
		s.block()
		return ErrSettingsUnavailable
	}
	// Cancellation during durable publication cannot undo the committed file.
	// Keep execution blocked rather than starting a generation after the request
	// expired; restart/readback will establish which approved state was committed.
	if err = ctx.Err(); err != nil {
		s.block()
		return err
	}
	monitor := s.newMonitor(c)
	if monitor == nil {
		s.block()
		return ErrSettingsUnavailable
	}
	s.mu.Lock()
	s.saved, s.config, s.monitor = next, c, monitor
	s.mu.Unlock()
	s.signal()
	return nil
}

// stopWorker is always called with operation held. Cancellation is joined even
// if the HTTP request expires; no newer generation starts while an old one lives.
func (s *Settings) stopWorker() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
		s.cancel, s.done = nil, nil
	}
}
func (s *Settings) block() {
	s.stopWorker()
	s.mu.Lock()
	s.blocked = true
	s.mu.Unlock()
	s.signal()
}
func (s *Settings) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Settings) Run(ctx context.Context) error {
	if s == nil {
		return ErrSettingsUnavailable
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrRunning
	}
	defer s.running.Store(false)
	defer func() {
		s.operation.Lock()
		s.stopWorker()
		s.operation.Unlock()
	}()
	for {
		s.operation.Lock()
		s.mu.RLock()
		blocked, enabled, monitor := s.blocked, s.config.enabled, s.monitor
		s.mu.RUnlock()
		if ctx.Err() != nil || blocked {
			s.operation.Unlock()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrSettingsUnavailable
		}
		if s.done != nil {
			select {
			case <-s.done:
				// Unexpected worker termination is not an invitation to retry.
				s.block()
				s.operation.Unlock()
				return ErrSettingsUnavailable
			default:
			}
		} else if enabled {
			if s.mode == "managed" && !s.diskMatches() {
				s.block()
				s.operation.Unlock()
				return ErrSettingsUnavailable
			}
			workerCtx, cancel := context.WithCancel(ctx)
			s.cancel, s.done = cancel, make(chan struct{})
			done := s.done
			go func() {
				if s.awaitCooldown(workerCtx) {
					_ = monitor.Run(workerCtx)
				}
				close(done)
				s.signal()
			}()
		}
		s.operation.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.wake:
		}
	}
}

// newMonitor preserves the existing sequential monitor while remembering a
// completion-based floor across browser changes. An interrupted attempt also
// consumes this cooldown; repeated save/enable/disable cannot become a probe API.
func (s *Settings) newMonitor(c Config) *Monitor {
	m := s.factory(c)
	if m == nil {
		return nil
	}
	check := m.check
	m.check = func(ctx context.Context, target target, profile string, started time.Time) Result {
		result := check(ctx, target, profile, started)
		// Keep time.Now's monotonic component: wall-clock changes must not
		// shorten the cross-generation floor. Only audit timestamps use UTC.
		next := s.now().Add(c.interval)
		s.mu.Lock()
		if next.After(s.nextAllowed) {
			s.nextAllowed = next
		}
		s.mu.Unlock()
		return result
	}
	return m
}
func (s *Settings) awaitCooldown(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		s.mu.RLock()
		next := s.nextAllowed
		s.mu.RUnlock()
		delay := next.Sub(s.now())
		if delay <= 0 {
			return true
		}
		if !s.wait(ctx, delay) {
			return false
		}
	}
}

func (s *Settings) diskMatches() bool {
	if lanstore.ValidateStateFile(s.file) != nil {
		return false
	}
	raw, err := lanconfig.ReadProtected(s.file, true, settingsFileLimit)
	defer clear(raw)
	return err == nil && sha256.Sum256(raw) == s.digest
}
func (s *Settings) write(next savedSettings, create bool) error {
	if lanstore.ValidateStateFile(s.file) != nil || !create && !s.diskMatches() {
		return ErrConfiguration
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > settingsFileLimit {
		return ErrConfiguration
	}
	defer clear(raw)
	dir := filepath.Dir(s.file)
	f, err := os.CreateTemp(dir, ".application-check-settings-")
	if err != nil {
		return ErrConfiguration
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || lanstore.ValidateStateFile(s.file) != nil || !create && !s.diskMatches() {
		return ErrConfiguration
	}
	if create {
		// Link is create-only. Never adopt a raced-in file or follow a symlink.
		if os.Link(tmp, s.file) != nil || os.Remove(tmp) != nil {
			return ErrConfiguration
		}
	} else if os.Rename(tmp, s.file) != nil {
		return ErrConfiguration
	}
	d, err := os.Open(dir)
	if err != nil {
		return ErrConfiguration
	}
	err, closeErr = d.Sync(), d.Close()
	if err != nil || closeErr != nil {
		return ErrConfiguration
	}
	check, err := lanconfig.ReadProtected(s.file, true, settingsFileLimit)
	defer clear(check)
	if err != nil || !bytes.Equal(check, raw) {
		return ErrConfiguration
	}
	s.digest = sha256.Sum256(raw)
	return nil
}
