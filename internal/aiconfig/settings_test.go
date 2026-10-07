package aiconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/analysis"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC)

const fixtureActor = "shared-administrator"

func token(c string) string  { return "cfg-" + strings.Repeat(c, 32) }
func device(c string) string { return "agent_" + strings.Repeat(c, 32) }
func fixture(t *testing.T, profile string) *Settings {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux protected settings")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir, "manager-fixture", profile)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func provider() Provider {
	return Provider{Revision: token("1"), BaseURL: "http://127.0.0.1:11434/v1", Model: "fixture-model", ApprovedOrigin: "http://127.0.0.1:11434"}
}
func scope() Scope {
	return Scope{Revision: token("2"), ConfigRevision: token("1"), Enabled: true, DeviceIDs: []string{device("b"), device("a")}, DataScope: analysis.HealthDataScope}
}
func snapshot(t *testing.T, s *Settings) Snapshot {
	t.Helper()
	v, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func configured(t *testing.T, profile string) *Settings {
	t.Helper()
	s := fixture(t, profile)
	if err := s.SaveProvider(provider(), false, fixtureActor, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScope(token("1"), scope(), fixtureActor, fixtureNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return s
}
func reopen(t *testing.T, s *Settings) *Settings {
	t.Helper()
	next, err := New(filepath.Dir(s.file), "manager-fixture", s.saved.Profile)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
func TestMissingDefaultsOffAndMatchingRestartPreservesApproval(t *testing.T) {
	s := fixture(t, "http-test")
	v := snapshot(t, s)
	if v.Configured || v.Scope.Enabled || v.Provider.APIKey != "" || !validRevision(v.Provider.Revision) || !validRevision(v.Scope.Revision) {
		t.Fatal("missing state adopted configuration")
	}
	if !s.Matches("manager-fixture", "http-test") || s.Matches("other", "http-test") || s.Matches("manager-fixture", "tls") {
		t.Fatal("binding mismatch")
	}
	if got := snapshot(t, reopen(t, s)); !reflect.DeepEqual(v, got) {
		t.Fatal("inert revision changed on restart")
	}
	if err := s.SaveProvider(provider(), false, fixtureActor, fixtureNow); err != nil {
		t.Fatal(err)
	}
	input := scope()
	input.EnabledAt = fixtureNow.Add(-time.Hour)
	input.ApprovedAt = input.EnabledAt
	input.ApprovedBy = "forged-actor"
	if err := s.SaveScope(token("1"), input, fixtureActor, fixtureNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	v = snapshot(t, s)
	input.DeviceIDs[0] = device("c")
	if !v.Scope.EnabledAt.Equal(fixtureNow.Add(time.Second)) || v.Scope.ApprovedBy != fixtureActor || v.Scope.DeviceIDs[0] != device("a") {
		t.Fatal("approval time, actor or copied devices invalid")
	}
	if got := snapshot(t, reopen(t, s)); !reflect.DeepEqual(v, got) {
		t.Fatal("restart changed provider, generation or original consent")
	}
	v.Scope.DeviceIDs[0] = device("d")
	if snapshot(t, s).Scope.DeviceIDs[0] != device("a") {
		t.Fatal("snapshot retained caller-owned slice")
	}
	info, err := os.Stat(s.file)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("settings not private")
	}
}
func TestKeyedStorageNeedsExplicitAcknowledgmentAndTLS(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, ack := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_ack_%v", profile, ack), func(t *testing.T) {
				s := fixture(t, profile)
				p := provider()
				p.APIKey = "fixture-key-for-storage-only"
				err := s.SaveProvider(p, ack, fixtureActor, fixtureNow)
				if profile != "tls" || !ack {
					if err == nil || snapshot(t, s).Configured {
						t.Fatal("key stored without explicit secure approval")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				v := snapshot(t, s)
				if got := snapshot(t, reopen(t, s)); !reflect.DeepEqual(v, got) || got.Provider.APIKey != p.APIKey {
					t.Fatal("approved key not restored with same generation")
				}
				for _, value := range []any{p, &p, v, &v, s, *s, s.saved, &s.saved, diskEncoding(s.saved)} {
					for _, format := range []string{"%v", "%+v", "%#v"} {
						if strings.Contains(fmt.Sprintf(format, value), p.APIKey) {
							t.Fatal("credential leaked through formatting")
						}
					}
				}
				for _, value := range []any{p, &p, v, &v, s, *s, s.saved, &s.saved} {
					raw, err := json.Marshal(value)
					if err != nil || string(raw) != `{"redacted":true}` {
						t.Fatal("credential-capable value JSON not redacted")
					}
				}
			})
		}
	}
}
func TestReplacementAlwaysChangesGenerationAndDisablesScope(t *testing.T) {
	for _, change := range []string{"same", "url", "model", "key", "compatibility"} {
		t.Run(change, func(t *testing.T) {
			s := configured(t, "tls")
			old := snapshot(t, s)
			p := provider()
			p.Revision = token("3")
			switch change {
			case "url":
				p.BaseURL = "http://127.0.0.1:11435/v1"
				p.ApprovedOrigin = "http://127.0.0.1:11435"
			case "model":
				p.Model = "different"
			case "key":
				p.APIKey = "fixture-fresh-key"
			case "compatibility":
				p.UseLegacyMaxTokens = true
			}
			if err := s.SaveProvider(p, true, fixtureActor, fixtureNow.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
			v := snapshot(t, reopen(t, s))
			if v.Scope.Enabled || v.Scope.ApprovedBy != "" || !v.Scope.EnabledAt.IsZero() || len(v.Scope.DeviceIDs) != 0 || v.Provider.CredentialGeneration == old.Provider.CredentialGeneration || v.Provider.Revision == old.Provider.Revision {
				t.Fatal("replacement reused approval or generation")
			}
		})
	}
}
func TestDisableAndForgetDurableTombstone(t *testing.T) {
	s := configured(t, "tls")
	if err := s.SaveScope(token("1"), Scope{Revision: token("3"), ConfigRevision: token("1"), DeviceIDs: []string{}, DataScope: analysis.HealthDataScope}, fixtureActor, fixtureNow.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	v := snapshot(t, reopen(t, s))
	if v.Scope.Enabled || !v.Configured || v.LastAction != "disable" {
		t.Fatal("disable not durable")
	}
	if err := s.Forget(token("4"), token("5"), fixtureActor, fixtureNow.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	v = snapshot(t, reopen(t, s))
	if v.Configured || v.Scope.Enabled || v.Provider.APIKey != "" || v.Provider.BaseURL != "" || v.LastAction != "forget" {
		t.Fatal("forgotten provider resurrected")
	}
	if _, err := os.Stat(s.file); err != nil {
		t.Fatal("forget unlinked tombstone")
	}
}
func TestInvalidBindingsFilesAndStrictRecordsFailClosed(t *testing.T) {
	for _, issue := range []string{"manager", "profile", "mode", "directory-mode", "symlink", "parent-symlink", "hardlink", "directory", "corrupt", "partial", "unknown", "duplicate", "null", "null-device", "alias", "trailing", "schema", "generation", "mutated-url", "mutated-model", "mutated-flag", "mutated-key", "binding", "unapproved-key", "scope-provider", "actor", "scope-time", "scope-order", "substituted-device", "substituted-actor", "substituted-time", "substituted-scope-revision", "unconfigured-key", "oversized"} {
		t.Run(issue, func(t *testing.T) {
			s := configured(t, "tls")
			manager, profile := "manager-fixture", "tls"
			dir := filepath.Dir(s.file)
			raw, err := os.ReadFile(s.file)
			if err != nil {
				t.Fatal(err)
			}
			switch issue {
			case "manager":
				manager = "other"
			case "profile":
				profile = "http-test"
			case "mode":
				if err = os.Chmod(s.file, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err = os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				os.Rename(s.file, s.file+".old")
				os.Symlink(s.file+".old", s.file)
			case "parent-symlink":
				link := dir + "-link"
				if err = os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(link) })
				dir = link
			case "hardlink":
				if err = os.Link(s.file, s.file+".link"); err != nil {
					t.Fatal(err)
				}
			case "directory":
				os.Remove(s.file)
				os.Mkdir(s.file, 0700)
			case "corrupt":
				raw = []byte("{")
			case "partial":
				raw = []byte(`{"schemaVersion":"tracebolt.ai-settings.v1"}`)
			case "unknown":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "duplicate":
				raw = append([]byte(`{"enabled":true,`), raw[1:]...)
			case "null":
				raw = bytes.Replace(raw, []byte(`"model":"fixture-model"`), []byte(`"model":null`), 1)
			case "null-device":
				raw = bytes.Replace(raw, []byte(`"deviceIds":[`), []byte(`"deviceIds":[null,`), 1)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"model":`), []byte(`"Model":`), 1)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "schema":
				raw = bytes.Replace(raw, []byte(SchemaVersion), []byte("tracebolt.ai-settings.v0"), 1)
			case "generation":
				raw = bytes.Replace(raw, []byte(s.saved.CredentialGeneration), []byte("unbound"), 1)
			case "mutated-url":
				raw = bytes.ReplaceAll(raw, []byte("127.0.0.1:11434"), []byte("127.0.0.1:11435"))
			case "mutated-model":
				raw = bytes.Replace(raw, []byte("fixture-model"), []byte("replacement-model"), 1)
			case "mutated-flag":
				raw = bytes.Replace(raw, []byte(`"useLegacyMaxTokens":false`), []byte(`"useLegacyMaxTokens":true`), 1)
			case "mutated-key":
				raw = bytes.Replace(raw, []byte(`"apiKey":""`), []byte(`"apiKey":"fixture-key"`), 1)
				raw = bytes.Replace(raw, []byte(`"keyStorageAcknowledged":false`), []byte(`"keyStorageAcknowledged":true`), 1)
			case "binding":
				raw = bytes.Replace(raw, []byte(`"scopeProviderBinding":"`+s.saved.ProviderBinding+`"`), []byte(`"scopeProviderBinding":"`+strings.Repeat("a", 64)+`"`), 1)
			case "unapproved-key":
				raw = bytes.Replace(raw, []byte(`"apiKey":""`), []byte(`"apiKey":"fixture-stolen-key"`), 1)
			case "scope-provider":
				raw = bytes.Replace(raw, []byte(`"scopeConfigRevision":"`+token("1")+`"`), []byte(`"scopeConfigRevision":"`+token("3")+`"`), 1)
			case "actor":
				raw = bytes.Replace(raw, []byte(`"approvedBy":"shared-administrator"`), []byte(`"approvedBy":"other"`), 1)
			case "scope-time":
				raw = bytes.Replace(raw, []byte(`"enabledAt":"2026-10-07T07:00:01Z"`), []byte(`"enabledAt":"2026-10-07T06:00:01Z"`), 1)
			case "substituted-device":
				raw = bytes.Replace(raw, []byte(device("b")), []byte(device("c")), 1)
			case "substituted-actor":
				raw = bytes.ReplaceAll(raw, []byte(`"approvedBy":"shared-administrator"`), []byte(`"approvedBy":"operator_11111111111111111111111111111111"`))
				raw = bytes.ReplaceAll(raw, []byte(`"lastActor":"shared-administrator"`), []byte(`"lastActor":"operator_11111111111111111111111111111111"`))
			case "substituted-time":
				raw = bytes.ReplaceAll(raw, []byte("2026-10-07T07:00:01Z"), []byte("2026-10-07T08:00:01Z"))
			case "substituted-scope-revision":
				raw = bytes.Replace(raw, []byte(`"scopeRevision":"`+token("2")+`"`), []byte(`"scopeRevision":"`+token("3")+`"`), 1)
			case "scope-order":
				raw = bytes.Replace(raw, []byte(`"`+device("a")+`","`+device("b")+`"`), []byte(`"`+device("b")+`","`+device("a")+`"`), 1)
			case "unconfigured-key":
				raw = bytes.Replace(raw, []byte(`"configured":true`), []byte(`"configured":false`), 1)
			case "oversized":
				raw = bytes.Repeat([]byte(" "), maxSettingsBytes+1)
			}
			switch issue {
			case "manager", "profile", "mode", "directory-mode", "symlink", "parent-symlink", "hardlink", "directory":
			default:
				if err = os.WriteFile(s.file, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = New(dir, manager, profile); err == nil {
				t.Fatal("unsafe record adopted")
			}
			if issue != "manager" && issue != "profile" && issue != "parent-symlink" {
				if got, err := s.Snapshot(); err == nil || got.Configured || got.Scope.Enabled {
					t.Fatal("unsafe current record stayed usable")
				}
			}
		})
	}
}
func TestInvalidChangesAreNonmutatingAndStaleWritesConflict(t *testing.T) {
	for _, issue := range []string{"bad-token", "same-token", "generation", "bad-actor", "zero-time", "backdated", "private-url", "origin", "remote-no-key", "remote-no-ack", "key-echo", "bad-model", "unknown-scope", "empty-devices", "duplicate-devices", "bad-device", "too-many", "nil-devices", "stale-config", "stale-scope", "wrong-config", "disable-with-devices"} {
		t.Run(issue, func(t *testing.T) {
			s := configured(t, "tls")
			before := snapshot(t, s)
			rawBefore, _ := os.ReadFile(s.file)
			p := provider()
			p.Revision = token("3")
			sc := scope()
			sc.Revision = token("3")
			actor := fixtureActor
			now := fixtureNow.Add(2 * time.Second)
			rev := token("1")
			useScope := false
			switch issue {
			case "bad-token":
				p.Revision = "cfg-bad"
			case "same-token":
				p.Revision = token("1")
			case "generation":
				p.CredentialGeneration = before.Provider.CredentialGeneration
			case "bad-actor":
				actor = "admin"
			case "zero-time":
				now = time.Time{}
			case "backdated":
				now = fixtureNow.Add(-time.Second)
			case "private-url":
				p.BaseURL = "https://10.0.0.1/v1"
				p.ApprovedOrigin = "https://10.0.0.1"
				p.AllowRemoteEvidence = true
				p.APIKey = "fixture-private-key"
			case "origin":
				p.ApprovedOrigin = "http://127.0.0.1:1234"
			case "remote-no-key":
				p.BaseURL = "https://provider.example.test/v1"
				p.ApprovedOrigin = "https://provider.example.test"
				p.AllowRemoteEvidence = true
			case "remote-no-ack":
				p.BaseURL = "https://provider.example.test/v1"
				p.ApprovedOrigin = "https://provider.example.test"
				p.APIKey = "fixture-key"
			case "key-echo":
				p.APIKey = "fixture-model"
			case "bad-model":
				p.Model = "model\nsecret"
			case "unknown-scope":
				useScope = true
				sc.DataScope = "raw-logs"
			case "empty-devices":
				useScope = true
				sc.DeviceIDs = []string{}
			case "duplicate-devices":
				useScope = true
				sc.DeviceIDs = []string{device("a"), device("a")}
			case "bad-device":
				useScope = true
				sc.DeviceIDs = []string{"agent_bad"}
			case "too-many":
				useScope = true
				sc.DeviceIDs = make([]string, 26)
			case "nil-devices":
				useScope = true
				sc.DeviceIDs = nil
			case "stale-config":
				useScope = true
				rev = token("9")
			case "stale-scope":
				useScope = true
				sc.Revision = token("2")
			case "wrong-config":
				useScope = true
				sc.ConfigRevision = token("9")
			case "disable-with-devices":
				useScope = true
				sc.Enabled = false
			}
			var err error
			if useScope {
				err = s.SaveScope(rev, sc, actor, now)
			} else {
				err = s.SaveProvider(p, true, actor, now)
			}
			if err == nil {
				t.Fatal("invalid update accepted")
			}
			after := snapshot(t, s)
			rawAfter, _ := os.ReadFile(s.file)
			if !reflect.DeepEqual(before, after) || !bytes.Equal(rawBefore, rawAfter) {
				t.Fatal("failed validation changed settings")
			}
		})
	}
}
func TestExternalChangesAndFailedWritesLatchBlocked(t *testing.T) {
	for _, change := range []string{"missing", "valid-other-controller", "insecure", "uncertain-disable"} {
		t.Run(change, func(t *testing.T) {
			s := configured(t, "tls")
			original, _ := os.ReadFile(s.file)
			switch change {
			case "missing":
				os.Remove(s.file)
			case "valid-other-controller":
				other := reopen(t, s)
				if err := other.Forget(token("3"), token("4"), fixtureActor, fixtureNow.Add(2*time.Second)); err != nil {
					t.Fatal(err)
				}
			case "insecure":
				os.Chmod(s.file, 0644)
			case "uncertain-disable":
				s.afterPublish = func() error { return errors.New("fixture directory synchronization failed") }
			}
			err := s.SaveScope(token("1"), Scope{Revision: token("5"), DeviceIDs: []string{}, DataScope: analysis.HealthDataScope}, fixtureActor, fixtureNow.Add(3*time.Second))
			if err != ErrUnavailable {
				t.Fatalf("wanted blocked result, got %v", err)
			}
			if _, err = s.Snapshot(); err != ErrUnavailable {
				t.Fatal("failed write remained usable")
			}
			if change == "uncertain-disable" {
				if _, err := New(filepath.Dir(s.file), "manager-fixture", "tls"); err == nil {
					t.Fatal("uncertain disable fence was auto-cleared")
				}
			}
			os.WriteFile(s.file, original, 0600)
			os.Chmod(s.file, 0600)
			s.afterPublish = nil
			if err = s.SaveProvider(Provider{}, false, fixtureActor, fixtureNow.Add(4*time.Second)); err != ErrUnavailable {
				t.Fatal("uncertainty auto-healed")
			}
		})
	}
}
func TestConstructReadAndSaveNeverContactProvider(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	s := fixture(t, "tls")
	p := provider()
	p.BaseURL = server.URL + "/v1"
	p.ApprovedOrigin = server.URL
	if err := s.SaveProvider(p, false, fixtureActor, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveScope(p.Revision, scope(), fixtureActor, fixtureNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = snapshot(t, reopen(t, s))
	if calls.Load() != 0 {
		t.Fatal("configuration contacted loopback provider")
	}
	var dnsCalls atomic.Int32
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		dnsCalls.Add(1)
		return nil, errors.New("fixture DNS should not run")
	}}
	defer func() { net.DefaultResolver = oldResolver }()
	p = Provider{Revision: token("3"), BaseURL: "https://fixture-provider.invalid/v1", ApprovedOrigin: "https://fixture-provider.invalid", Model: "fixture-model", APIKey: "fixture-key", AllowRemoteEvidence: true}
	if err := s.SaveProvider(p, true, fixtureActor, fixtureNow.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = snapshot(t, reopen(t, s))
	if dnsCalls.Load() != 0 {
		t.Fatal("configuration resolved provider DNS")
	}
}

func TestPendingFenceBlocksRestartAtEveryUncertainChange(t *testing.T) {
	for _, operation := range []string{"replace", "enable", "disable", "forget"} {
		for _, stage := range []string{"after-fence", "after-publication"} {
			t.Run(operation+"_"+stage, func(t *testing.T) {
				s := configured(t, "tls")
				failure := func() error { return context.Canceled }
				if stage == "after-fence" {
					s.afterFence = failure
				} else {
					s.afterPublish = failure
				}
				var err error
				switch operation {
				case "replace":
					p := provider()
					p.Revision = token("3")
					err = s.SaveProvider(p, false, fixtureActor, fixtureNow.Add(2*time.Second))
				case "enable":
					sc := scope()
					sc.Revision = token("3")
					err = s.SaveScope(token("1"), sc, fixtureActor, fixtureNow.Add(2*time.Second))
				case "disable":
					err = s.SaveScope(token("1"), Scope{Revision: token("3"), DeviceIDs: []string{}, DataScope: analysis.HealthDataScope}, fixtureActor, fixtureNow.Add(2*time.Second))
				case "forget":
					err = s.Forget(token("3"), token("4"), fixtureActor, fixtureNow.Add(2*time.Second))
				}
				if err != ErrUnavailable {
					t.Fatalf("uncertain mutation returned %v", err)
				}
				if _, err = s.Snapshot(); err != ErrUnavailable {
					t.Fatal("uncertain controller stayed usable")
				}
				info, err := os.Stat(s.fencePath())
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("pending fence absent or insecure")
				}
				if _, err = New(filepath.Dir(s.file), "manager-fixture", "tls"); err == nil {
					t.Fatal("restart adopted interrupted change")
				}
				if stage == "after-publication" && (operation == "disable" || operation == "forget") {
					raw, err := os.ReadFile(s.file)
					if err != nil {
						t.Fatal(err)
					}
					var disk savedRecord
					if decode(raw, &disk) != nil || disk.Enabled {
						t.Fatal("published off state lost")
					}
				}
			})
		}
	}
}
func TestPreexistingPendingFenceNeverAdoptedOrRemoved(t *testing.T) {
	for _, issue := range []string{"valid", "corrupt", "insecure", "symlink", "directory", "missing-settings"} {
		t.Run(issue, func(t *testing.T) {
			s := configured(t, "tls")
			path := s.fencePath()
			switch issue {
			case "symlink":
				if err := os.Symlink(s.file, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				raw := []byte(pendingMarker)
				mode := os.FileMode(0600)
				if issue == "corrupt" {
					raw = []byte("bad")
				}
				if issue == "insecure" {
					mode = 0644
				}
				if err := os.WriteFile(path, raw, mode); err != nil {
					t.Fatal(err)
				}
			}
			if issue == "missing-settings" {
				if err := os.Remove(s.file); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Snapshot(); err != ErrUnavailable {
				t.Fatal("existing fence ignored")
			}
			if _, err := New(filepath.Dir(s.file), "manager-fixture", "tls"); err == nil {
				t.Fatal("pending fence adopted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("pending fence removed automatically")
			}
		})
	}
}
func TestFailedFenceCreationCannotMutateRecord(t *testing.T) {
	s := configured(t, "tls")
	before, err := os.ReadFile(s.file)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(s.fencePath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err = s.Forget(token("3"), token("4"), fixtureActor, fixtureNow.Add(2*time.Second)); err != ErrUnavailable {
		t.Fatal("unsafe fence path ignored")
	}
	after, err := os.ReadFile(s.file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed fence mutated record")
	}
}
