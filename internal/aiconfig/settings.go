// Package aiconfig owns protected, restart-stable AI configuration and consent.
// It never makes a provider request, collects evidence, or grants endpoint access.
package aiconfig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/analysis"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const SettingsFile = "ai-settings.json"
const PendingFile = "ai-settings.pending"
const pendingMarker = "tracebolt.ai-settings-pending.v1\n"
const SchemaVersion = "tracebolt.ai-settings.v1"
const maxSettingsBytes = 16384

var ErrConfiguration = errors.New("invalid_ai_settings")
var ErrConflict = errors.New("ai_settings_changed")
var ErrUnavailable = errors.New("ai_settings_unavailable")
var managerIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// Provider and Snapshot are backend-only. Formatting/JSON always redact them.
// CredentialGeneration is controller-owned; SaveProvider requires it empty.
// A fresh Revision is required even when replacing a provider with identical data.
type Provider struct {
	Revision             string
	CredentialGeneration string
	BaseURL              string
	Model                string
	APIKey               string `json:"-"`
	ApprovedOrigin       string
	AllowRemoteEvidence  bool
	UseLegacyMaxTokens   bool
}

func (Provider) String() string               { return "aiconfig.Provider{redacted}" }
func (Provider) GoString() string             { return "aiconfig.Provider{redacted}" }
func (Provider) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type Scope struct {
	Revision       string
	ConfigRevision string
	Enabled        bool
	EnabledAt      time.Time
	DeviceIDs      []string
	DataScope      string
	ApprovedBy     string
	ApprovedAt     time.Time
}

type Snapshot struct {
	Configured        bool
	Provider          Provider
	Scope             Scope
	ManagerInstanceID string
	Profile           string
	LastActor         string
	LastAction        string
	ChangedAt         time.Time
}

func (Snapshot) String() string               { return "aiconfig.Snapshot{redacted}" }
func (Snapshot) GoString() string             { return "aiconfig.Snapshot{redacted}" }
func (Snapshot) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

// savedRecord is a single coherent file. Its separate private encoding type is
// the only route that serializes credentials; neither is returned by an API.
type savedRecord struct {
	SchemaVersion          string    `json:"schemaVersion"`
	ManagerInstanceID      string    `json:"managerInstanceId"`
	Profile                string    `json:"profile"`
	Configured             bool      `json:"configured"`
	ConfigRevision         string    `json:"configRevision"`
	CredentialGeneration   string    `json:"credentialGeneration"`
	ProviderBinding        string    `json:"providerBinding"`
	BaseURL                string    `json:"baseURL"`
	Model                  string    `json:"model"`
	APIKey                 string    `json:"apiKey"`
	ApprovedOrigin         string    `json:"approvedOrigin"`
	AllowRemoteEvidence    bool      `json:"allowRemoteEvidence"`
	UseLegacyMaxTokens     bool      `json:"useLegacyMaxTokens"`
	KeyStorageAcknowledged bool      `json:"keyStorageAcknowledged"`
	ProviderApprovedBy     string    `json:"providerApprovedBy"`
	ProviderApprovedAt     time.Time `json:"providerApprovedAt"`
	ScopeRevision          string    `json:"scopeRevision"`
	ScopeConfigRevision    string    `json:"scopeConfigRevision"`
	ScopeProviderBinding   string    `json:"scopeProviderBinding"`
	ScopeBinding           string    `json:"scopeBinding"`
	Enabled                bool      `json:"enabled"`
	EnabledAt              time.Time `json:"enabledAt"`
	DeviceIDs              []string  `json:"deviceIds"`
	DataScope              string    `json:"dataScope"`
	ApprovedBy             string    `json:"approvedBy"`
	ApprovedAt             time.Time `json:"approvedAt"`
	LastActor              string    `json:"lastActor"`
	LastAction             string    `json:"lastAction"`
	ChangedAt              time.Time `json:"changedAt"`
}

func (savedRecord) String() string               { return "aiconfig.savedRecord{redacted}" }
func (savedRecord) GoString() string             { return "aiconfig.savedRecord{redacted}" }
func (savedRecord) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

type diskEncoding savedRecord

func (diskEncoding) String() string   { return "aiconfig.diskEncoding{redacted}" }
func (diskEncoding) GoString() string { return "aiconfig.diskEncoding{redacted}" }

// Settings is serialized internally as well as by the API admission/publication
// mutex. Any protection/content failure latches blocked; this process never
// auto-adopts a changed file or retries an uncertain write.
type Settings struct {
	mu      *sync.Mutex
	file    string
	saved   savedRecord
	digest  [32]byte
	blocked bool
	// Test-only durability fault seams; no callback is provided by production.
	afterPublish func() error
	afterFence   func() error
}

func (Settings) String() string               { return "aiconfig.Settings{redacted}" }
func (Settings) GoString() string             { return "aiconfig.Settings{redacted}" }
func (Settings) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func revision() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", ErrConfiguration
	}
	return "cfg-" + hex.EncodeToString(b[:]), nil
}
func validRevision(v string) bool { return enrollmentcrypto.ValidID(v, "cfg-") }
func validActor(v string) bool {
	return v == "shared-administrator" || enrollmentcrypto.ValidID(v, "operator_")
}
func validTime(v time.Time) bool {
	return !v.IsZero() && v.Year() >= 2000 && v.Year() <= 9999
}

func New(stateDir, managerID, profile string) (*Settings, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || !managerIdentifier.MatchString(managerID) || profile != "tls" && profile != "http-test" {
		return nil, ErrConfiguration
	}
	s := &Settings{mu: &sync.Mutex{}, file: filepath.Join(stateDir, SettingsFile)}
	if lanstore.ValidateStateFile(s.file) != nil || !s.fenceAbsent() {
		return nil, ErrConfiguration
	}
	raw, err := lanconfig.ReadProtected(s.file, true, maxSettingsBytes)
	if err == nil {
		defer clear(raw)
		if decode(raw, &s.saved) != nil || s.saved.validate(managerID, profile) != nil {
			return nil, ErrConfiguration
		}
		s.digest = sha256.Sum256(raw)
		return s, nil
	}
	if _, statErr := os.Lstat(s.file); !os.IsNotExist(statErr) {
		return nil, ErrConfiguration
	}
	rev, err := revision()
	if err != nil {
		return nil, err
	}
	s.saved = savedRecord{SchemaVersion: SchemaVersion, ManagerInstanceID: managerID, Profile: profile, ConfigRevision: rev, ScopeRevision: rev, DataScope: analysis.HealthDataScope, DeviceIDs: []string{}}
	if err = s.write(s.saved, true); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Settings) Matches(managerID, profile string) bool {
	if s == nil || s.mu == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saved.ManagerInstanceID == managerID && s.saved.Profile == profile
}

// Snapshot returns a detached backend snapshot only after rechecking the exact
// protected record. The caller must treat any error as provider/scope blocked.
func (s *Settings) Snapshot() (Snapshot, error) {
	if s == nil || s.mu == nil {
		return Snapshot{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(); err != nil {
		return Snapshot{}, err
	}
	r := s.saved
	return Snapshot{Configured: r.Configured, Provider: r.provider(), Scope: Scope{Revision: r.ScopeRevision, ConfigRevision: r.ScopeConfigRevision, Enabled: r.Enabled, EnabledAt: r.EnabledAt, DeviceIDs: append([]string{}, r.DeviceIDs...), DataScope: r.DataScope, ApprovedBy: r.ApprovedBy, ApprovedAt: r.ApprovedAt}, ManagerInstanceID: r.ManagerInstanceID, Profile: r.Profile, LastActor: r.LastActor, LastAction: r.LastAction, ChangedAt: r.ChangedAt}, nil
}

// providerBinding is a private consistency check, not a public credential hash
// or a defense against compromise of the manager account. It binds the opaque
// generation to the exact stored provider and manager/profile.
func (r savedRecord) providerBinding() string {
	raw, err := json.Marshal([]any{r.SchemaVersion, r.ManagerInstanceID, r.Profile, r.ConfigRevision, r.CredentialGeneration, r.BaseURL, r.Model, r.APIKey, r.ApprovedOrigin, r.AllowRemoteEvidence, r.UseLegacyMaxTokens, r.KeyStorageAcknowledged, r.ProviderApprovedBy, r.ProviderApprovedAt})
	if err != nil {
		return ""
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// scopeBinding detects accidental changes to the exact consent boundary and
// original approval metadata. It is private and is not an authentication tag.
func (r savedRecord) scopeBinding() string {
	if !r.Enabled {
		return ""
	}
	raw, err := json.Marshal([]any{r.ProviderBinding, r.ScopeRevision, r.ScopeConfigRevision, r.Enabled, r.DeviceIDs, r.EnabledAt, r.ApprovedBy, r.ApprovedAt})
	if err != nil {
		return ""
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func (r savedRecord) provider() Provider {
	return Provider{Revision: r.ConfigRevision, CredentialGeneration: r.CredentialGeneration, BaseURL: r.BaseURL, Model: r.Model, APIKey: r.APIKey, ApprovedOrigin: r.ApprovedOrigin, AllowRemoteEvidence: r.AllowRemoteEvidence, UseLegacyMaxTokens: r.UseLegacyMaxTokens}
}
func validateProvider(p Provider, profile string) error {
	if !validRevision(p.Revision) || p.Model == "" || len(p.ApprovedOrigin) > 512 {
		return ErrConfiguration
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || p.ApprovedOrigin != u.Scheme+"://"+u.Host {
		return ErrConfiguration
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if !loopback && (u.Scheme != "https" || !p.AllowRemoteEvidence || p.APIKey == "") {
		return ErrConfiguration
	}
	if p.APIKey != "" && (profile != "tls" || strings.Contains(p.BaseURL, p.APIKey) || strings.Contains(p.Model, p.APIKey) || strings.Contains(p.ApprovedOrigin, p.APIKey)) {
		return ErrConfiguration
	}
	allowed := []string{}
	if !loopback {
		allowed = append(allowed, p.ApprovedOrigin)
	}
	// Constructor uses the exact existing endpoint/key/model policy. It performs
	// no DNS resolution, dialing, test request, or discovery.
	if _, err = analysis.NewOpenAIProvider(analysis.OpenAIConfig{BaseURL: p.BaseURL, Model: p.Model, APIKey: p.APIKey, APIKeyOrigin: p.ApprovedOrigin, AllowedHTTPSOrigins: allowed, UseLegacyMaxTokens: p.UseLegacyMaxTokens}); err != nil {
		return ErrConfiguration
	}
	return nil
}

func (s *Settings) changeAllowed(actor string, now time.Time) error {
	if err := s.check(); err != nil {
		return err
	}
	if !validActor(actor) || !validTime(now) || !s.saved.ChangedAt.IsZero() && now.Before(s.saved.ChangedAt) {
		return ErrConfiguration
	}
	return nil
}
func (s *Settings) fresh(token string) bool {
	return validRevision(token) && token != s.saved.ConfigRevision && token != s.saved.ScopeRevision
}
func (r *savedRecord) clearScope(rev string) {
	r.ScopeRevision = rev
	r.ScopeConfigRevision = ""
	r.ScopeProviderBinding = ""
	r.ScopeBinding = ""
	r.Enabled = false
	r.EnabledAt = time.Time{}
	r.DeviceIDs = []string{}
	r.DataScope = analysis.HealthDataScope
	r.ApprovedBy = ""
	r.ApprovedAt = time.Time{}
}
func (r *savedRecord) audit(action, actor string, now time.Time) {
	r.LastAction = action
	r.LastActor = actor
	r.ChangedAt = now.UTC()
}
func (s *Settings) commit(next savedRecord) error {
	if next.validate(s.saved.ManagerInstanceID, s.saved.Profile) != nil {
		return ErrConfiguration
	}
	if err := s.write(next, false); err != nil {
		s.blocked = true
		return ErrUnavailable
	}
	s.saved = next
	return nil
}

// SaveProvider always creates a new credential identity and invalidates consent.
// No previously stored key is implicitly reused. APIKey is the complete new key.
func (s *Settings) SaveProvider(p Provider, acknowledgeKeyStorage bool, actor string, now time.Time) error {
	if s == nil || s.mu == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.changeAllowed(actor, now); err != nil {
		return err
	}
	if !validRevision(p.Revision) || p.CredentialGeneration != "" || p.APIKey != "" && !acknowledgeKeyStorage || validateProvider(p, s.saved.Profile) != nil {
		return ErrConfiguration
	}
	if !s.fresh(p.Revision) {
		return ErrConflict
	}
	generation, err := revision()
	if err != nil {
		return err
	}
	next := s.saved
	next.Configured = true
	next.ConfigRevision = p.Revision
	next.CredentialGeneration = generation
	next.BaseURL = p.BaseURL
	next.Model = p.Model
	next.APIKey = p.APIKey
	next.ApprovedOrigin = p.ApprovedOrigin
	next.AllowRemoteEvidence = p.AllowRemoteEvidence
	next.UseLegacyMaxTokens = p.UseLegacyMaxTokens
	next.KeyStorageAcknowledged = p.APIKey != "" && acknowledgeKeyStorage
	next.ProviderApprovedBy = actor
	next.ProviderApprovedAt = now.UTC()
	next.ProviderBinding = next.providerBinding()
	next.clearScope(p.Revision)
	next.audit("replace", actor, now)
	return s.commit(next)
}

// SaveScope takes the expected provider revision and a fresh scope revision.
// Enabling is a new explicit approval at now, never a restored/backdated grant.
// The API must independently validate device authority and evidence approval.
func (s *Settings) SaveScope(configRevision string, scope Scope, actor string, now time.Time) error {
	if s == nil || s.mu == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.changeAllowed(actor, now); err != nil {
		return err
	}
	if !validRevision(configRevision) || !validRevision(scope.Revision) || scope.DataScope != analysis.HealthDataScope || scope.DeviceIDs == nil || len(scope.DeviceIDs) > 25 {
		return ErrConfiguration
	}
	if configRevision != s.saved.ConfigRevision || !s.fresh(scope.Revision) {
		return ErrConflict
	}
	if scope.ConfigRevision != "" && scope.ConfigRevision != configRevision {
		return ErrConflict
	}
	if scope.Enabled && (!s.saved.Configured || len(scope.DeviceIDs) == 0) || !scope.Enabled && len(scope.DeviceIDs) != 0 {
		return ErrConfiguration
	}
	ids := append([]string{}, scope.DeviceIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !enrollmentcrypto.ValidID(id, "agent_") || i > 0 && ids[i-1] == id {
			return ErrConfiguration
		}
	}
	next := s.saved
	next.clearScope(scope.Revision)
	if scope.Enabled {
		next.Enabled = true
		next.EnabledAt = now.UTC()
		next.DeviceIDs = ids
		next.ScopeConfigRevision = configRevision
		next.ScopeProviderBinding = next.ProviderBinding
		next.ApprovedBy = actor
		next.ApprovedAt = now.UTC()
		next.audit("enable", actor, now)
		next.ScopeBinding = next.scopeBinding()
	} else {
		next.audit("disable", actor, now)
	}
	return s.commit(next)
}

// Forget persists an off tombstone with fresh revisions. It never unlinks the
// settings file, so a normal restart cannot restore the previous provider/key.
func (s *Settings) Forget(configRevision, scopeRevision, actor string, now time.Time) error {
	if s == nil || s.mu == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.changeAllowed(actor, now); err != nil {
		return err
	}
	if !validRevision(configRevision) || !validRevision(scopeRevision) {
		return ErrConfiguration
	}
	if !s.fresh(configRevision) || !s.fresh(scopeRevision) {
		return ErrConflict
	}
	next := savedRecord{SchemaVersion: SchemaVersion, ManagerInstanceID: s.saved.ManagerInstanceID, Profile: s.saved.Profile, ConfigRevision: configRevision}
	next.clearScope(scopeRevision)
	next.audit("forget", actor, now)
	return s.commit(next)
}

func (r savedRecord) validate(managerID, profile string) error {
	if r.SchemaVersion != SchemaVersion || r.ManagerInstanceID != managerID || r.Profile != profile || !managerIdentifier.MatchString(managerID) || profile != "tls" && profile != "http-test" || !validRevision(r.ConfigRevision) || !validRevision(r.ScopeRevision) || r.DataScope != analysis.HealthDataScope || r.DeviceIDs == nil || len(r.DeviceIDs) > 25 {
		return ErrConfiguration
	}
	if r.LastAction == "" {
		if r.LastActor != "" || !r.ChangedAt.IsZero() || r.Configured || r.Enabled {
			return ErrConfiguration
		}
	} else if !validActor(r.LastActor) || !validTime(r.ChangedAt) || r.LastAction != "replace" && r.LastAction != "enable" && r.LastAction != "disable" && r.LastAction != "forget" {
		return ErrConfiguration
	}
	if r.LastAction == "replace" && (!r.Configured || r.Enabled || r.ConfigRevision != r.ScopeRevision) {
		return ErrConfiguration
	}
	if r.Configured {
		if !validActor(r.ProviderApprovedBy) || !validTime(r.ProviderApprovedAt) || r.ProviderApprovedAt.After(r.ChangedAt) || !validRevision(r.CredentialGeneration) || r.ProviderBinding == "" || r.ProviderBinding != r.providerBinding() || validateProvider(r.provider(), profile) != nil || r.KeyStorageAcknowledged != (r.APIKey != "") || r.LastAction == "forget" {
			return ErrConfiguration
		}
	} else if r.ProviderApprovedBy != "" || !r.ProviderApprovedAt.IsZero() || r.ProviderBinding != "" || r.CredentialGeneration != "" || r.BaseURL != "" || r.Model != "" || r.APIKey != "" || r.ApprovedOrigin != "" || r.AllowRemoteEvidence || r.UseLegacyMaxTokens || r.KeyStorageAcknowledged || r.Enabled {
		return ErrConfiguration
	}
	if r.Enabled {
		if r.ScopeBinding == "" || r.ScopeBinding != r.scopeBinding() || !r.Configured || r.ScopeRevision == r.ConfigRevision || r.ScopeProviderBinding != r.ProviderBinding || r.ScopeConfigRevision != r.ConfigRevision || r.LastAction != "enable" || !validTime(r.EnabledAt) || !r.EnabledAt.Equal(r.ApprovedAt) || !r.ApprovedAt.Equal(r.ChangedAt) || !validActor(r.ApprovedBy) || r.ApprovedBy != r.LastActor || len(r.DeviceIDs) == 0 {
			return ErrConfiguration
		}
		for i, id := range r.DeviceIDs {
			if !enrollmentcrypto.ValidID(id, "agent_") || i > 0 && r.DeviceIDs[i-1] >= id {
				return ErrConfiguration
			}
		}
	} else if r.ScopeBinding != "" || r.ScopeProviderBinding != "" || r.ScopeConfigRevision != "" || !r.EnabledAt.IsZero() || len(r.DeviceIDs) != 0 || r.ApprovedBy != "" || !r.ApprovedAt.IsZero() || r.LastAction == "enable" {
		return ErrConfiguration
	}
	return nil
}

var recordFields = []string{"schemaVersion", "managerInstanceId", "profile", "configured", "configRevision", "credentialGeneration", "providerBinding", "baseURL", "model", "apiKey", "approvedOrigin", "allowRemoteEvidence", "useLegacyMaxTokens", "keyStorageAcknowledged", "providerApprovedBy", "providerApprovedAt", "scopeRevision", "scopeConfigRevision", "scopeProviderBinding", "scopeBinding", "enabled", "enabledAt", "deviceIds", "dataScope", "approvedBy", "approvedAt", "lastActor", "lastAction", "changedAt"}

// StrictObject is scalar-only; this sibling parser additionally permits the one
// bounded typed device-ID array and requires every versioned field exactly once.
func decode(raw []byte, out *savedRecord) error {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, utf8.RuneError) {
		return ErrConfiguration
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrConfiguration
	}
	allowed := map[string]bool{}
	for _, k := range recordFields {
		allowed[k] = true
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return ErrConfiguration
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrConfiguration
		}
		value = bytes.TrimSpace(value)
		if bytes.Equal(value, []byte("null")) || len(value) == 0 || value[0] == '{' || value[0] == '[' && key != "deviceIds" {
			return ErrConfiguration
		}
		if key == "deviceIds" {
			var ids []json.RawMessage
			if json.Unmarshal(value, &ids) != nil || len(ids) > 25 {
				return ErrConfiguration
			}
			for _, id := range ids {
				if bytes.Equal(bytes.TrimSpace(id), []byte("null")) {
					return ErrConfiguration
				}
			}
		}
		if value[0] == '"' {
			var str string
			if json.Unmarshal(value, &str) != nil || strings.ContainsRune(str, utf8.RuneError) {
				return ErrConfiguration
			}
		}
	}
	if _, err = d.Token(); err != nil || len(seen) != len(allowed) {
		return ErrConfiguration
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrConfiguration
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrConfiguration
	}
	return nil
}

func (s *Settings) fencePath() string { return filepath.Join(filepath.Dir(s.file), PendingFile) }
func (s *Settings) fenceAbsent() bool {
	path := s.fencePath()
	if lanstore.ValidateStateFile(path) != nil {
		return false
	}
	_, err := os.Lstat(path)
	return os.IsNotExist(err)
}
func (s *Settings) checkRecord() error {
	if lanstore.ValidateStateFile(s.file) != nil {
		return ErrUnavailable
	}
	raw, err := lanconfig.ReadProtected(s.file, true, maxSettingsBytes)
	defer clear(raw)
	if err != nil || sha256.Sum256(raw) != s.digest {
		return ErrUnavailable
	}
	return nil
}
func (s *Settings) check() error {
	if s.blocked {
		return ErrUnavailable
	}
	if !s.fenceAbsent() || s.checkRecord() != nil {
		s.blocked = true
		return ErrUnavailable
	}
	return nil
}
func syncDirectory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return ErrUnavailable
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	return nil
}

// A create-only fence is durable before the versioned record changes. Every
// unresolved fence blocks reads and restart; there is no automatic recovery.
// If the filesystem cannot persist even this fence, the failed mutation is not
// a durable revoke. Repair/review is required before resuming operation.
func (s *Settings) beginFence() error {
	if !s.fenceAbsent() {
		return ErrUnavailable
	}
	f, err := os.OpenFile(s.fencePath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnavailable
	}
	if _, err = io.WriteString(f, pendingMarker); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || syncDirectory(filepath.Dir(s.file)) != nil {
		return ErrUnavailable
	}
	check, err := lanconfig.ReadProtected(s.fencePath(), true, 128)
	defer clear(check)
	if err != nil || string(check) != pendingMarker {
		return ErrUnavailable
	}
	if s.afterFence != nil {
		return s.afterFence()
	}
	return nil
}
func (s *Settings) finishFence() error {
	check, err := lanconfig.ReadProtected(s.fencePath(), true, 128)
	defer clear(check)
	if err != nil || string(check) != pendingMarker || os.Remove(s.fencePath()) != nil {
		return ErrUnavailable
	}
	if syncDirectory(filepath.Dir(s.file)) != nil {
		// Best effort retains a visible blocker if the unlink was not known
		// durable. A failing disk cannot support a durable-revocation claim.
		_ = s.beginFence()
		return ErrUnavailable
	}
	return nil
}
func (s *Settings) write(next savedRecord, create bool) error {
	if lanstore.ValidateStateFile(s.file) != nil {
		return ErrUnavailable
	}
	if !create {
		if err := s.check(); err != nil {
			return err
		}
	}
	if err := s.beginFence(); err != nil {
		return ErrUnavailable
	}
	// Fence acquisition serializes other controllers. Recheck after acquiring
	// it, so a concurrent completed change cannot be overwritten from cache.
	if !create {
		if err := s.checkRecord(); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(diskEncoding(next))
	if err != nil || len(raw) > maxSettingsBytes {
		return ErrUnavailable
	}
	defer clear(raw)
	dir := filepath.Dir(s.file)
	f, err := os.CreateTemp(dir, ".ai-settings-")
	if err != nil {
		return ErrUnavailable
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrUnavailable
	}
	if create {
		// Create-only publication never adopts an unexpected concurrent file.
		if os.Link(tmp, s.file) != nil || os.Remove(tmp) != nil {
			return ErrUnavailable
		}
	} else if os.Rename(tmp, s.file) != nil {
		return ErrUnavailable
	}
	if s.afterPublish != nil {
		if err = s.afterPublish(); err != nil {
			return ErrUnavailable
		}
	}
	if syncDirectory(dir) != nil {
		return ErrUnavailable
	}
	check, err := lanconfig.ReadProtected(s.file, true, maxSettingsBytes)
	defer clear(check)
	if err != nil || !bytes.Equal(check, raw) {
		return ErrUnavailable
	}
	if err := s.finishFence(); err != nil {
		return err
	}
	s.digest = sha256.Sum256(raw)
	return nil
}
