package api

import (
	"context"
	"encoding/json"
	"localrmm/internal/aiconfig"
	"localrmm/internal/analysis"
	"localrmm/internal/model"
	"localrmm/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func persistentFixture(t *testing.T, o operatorFixture, profile string) *aiconfig.Settings {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	settings, err := aiconfig.New(dir, "manager-fixture", profile)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.app.configurePersistentAI(settings, profile == "tls"); err != nil {
		t.Fatal(err)
	}
	return settings
}
func savePersistentFixture(t *testing.T, o operatorFixture, csrf, base, key string, ack bool) (int, map[string]any) {
	t.Helper()
	response, v := o.call(t, "GET", "/api/ai/config", nil, "", nil)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	origin := strings.TrimSuffix(base, "/v1")
	body := map[string]any{"expectedRevision": v["revision"], "baseURL": base, "model": "fixture-model", "apiKey": key, "approvedOrigin": origin, "allowRemoteEvidence": strings.HasPrefix(base, "https://"), "useLegacyMaxTokens": false, "acknowledgeKeyStorage": ack}
	res, out := o.call(t, "POST", "/api/ai/config/persistent", body, csrf, nil)
	return res.StatusCode, out
}
func TestPersistentAIProviderAndScopeSurviveRestartWithoutReplay(t *testing.T) {
	o, source := investigationsFixture(t)
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	id := source.inputs[0].DeviceID
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	settings, err := aiconfig.New(dir, "manager-fixture", "tls")
	if err != nil {
		t.Fatal(err)
	}
	if err = o.app.configurePersistentAI(settings, true); err != nil {
		t.Fatal(err)
	}
	status, view := savePersistentFixture(t, o, csrf, "http://127.0.0.1:11434/v1", "", false)
	if status != 200 || view["storage"] != "protected-file" || view["resetsOnRestart"] != false {
		t.Fatal(status, view)
	}
	source.now = time.Now().UTC()
	proactiveEnable(t, o, csrf, id)
	original, err := settings.Snapshot()
	if err != nil || !original.Scope.Enabled {
		t.Fatal(err)
	}
	count := 0
	o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		count++
		return []byte(proactiveFindings), nil
	}})
	seedProactiveIncident(t, o, source)
	if err = o.app.runProactiveAI(context.Background(), o.app.health); err != nil || count != 1 {
		t.Fatal(err, count)
	}
	reopened, err := aiconfig.New(dir, "manager-fixture", "tls")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := New(o.app.store, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.configurePersistentAI(reopened, true); err != nil {
		t.Fatal(err)
	}
	if fresh.ai.config.Revision != original.Provider.Revision || fresh.ai.proactive.revision != original.Scope.Revision || !fresh.ai.proactive.enabledAt.Equal(original.Scope.EnabledAt) || !fresh.ai.proactive.enabled {
		t.Fatal("restart changed binding or original approval")
	}
	fresh.health = &healthMonitor{store: fresh.store, source: source}
	fresh.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
		count++
		return []byte(proactiveFindings), nil
	}})
	if err = fresh.runProactiveAI(context.Background(), fresh.health); err != nil || count != 1 {
		t.Fatal("restart replayed consumed incident", err, count)
	}
	persisted := proactiveSettings(t, o)
	if persisted["resetsOnRestart"] != false {
		t.Fatal("persisted scope shown temporary")
	}
}
func TestPersistentAIExplicitKeyStorageAndHTTPBoundary(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			o, _ := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			settings := persistentFixture(t, o, profile)
			secret := "synthetic-no-real-key"
			base := "https://example.invalid/v1"
			status, _ := savePersistentFixture(t, o, csrf, base, secret, false)
			if status != 400 {
				t.Fatal("key saved without explicit storage choice", status)
			}
			status, view := savePersistentFixture(t, o, csrf, base, secret, true)
			if profile == "http-test" {
				if status != 400 {
					t.Fatal("key persisted on plaintext operator profile")
				}
				return
			}
			if status != 200 {
				t.Fatal(status, view)
			}
			raw, _ := json.Marshal(view)
			if strings.Contains(string(raw), secret) || strings.Contains(string(raw), `"apiKey"`) {
				t.Fatal("key in public readback")
			}
			snap, err := settings.Snapshot()
			if err != nil || snap.Provider.APIKey != secret || snap.Provider.CredentialGeneration == "" {
				t.Fatal("credential not coherently bound", err)
			}
		})
	}
}
func TestPersistentAIMemoryOnlyReplacementAndClearDoNotResurrect(t *testing.T) {
	for _, action := range []string{"memory", "clear"} {
		t.Run(action, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			settings := persistentFixture(t, o, "tls")
			status, _ := savePersistentFixture(t, o, csrf, "http://127.0.0.1:11434/v1", "", false)
			if status != 200 {
				t.Fatal(status)
			}
			source.now = time.Now().UTC()
			proactiveEnable(t, o, csrf, source.inputs[0].DeviceID)
			if action == "clear" {
				res, _ := o.call(t, "POST", "/api/ai/config/clear", map[string]string{"expectedRevision": o.app.ai.config.Revision}, csrf, nil)
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
			} else {
				body := map[string]any{"expectedRevision": o.app.ai.config.Revision, "baseURL": "http://127.0.0.1:11434/v1", "model": "memory-model", "apiKey": "", "approvedOrigin": "http://127.0.0.1:11434", "allowRemoteEvidence": false, "useLegacyMaxTokens": false}
				res, v := o.call(t, "POST", "/api/ai/config", body, csrf, nil)
				if res.StatusCode != 200 || v["storage"] != "memory-only" {
					t.Fatal(res.StatusCode, v)
				}
			}
			snap, err := settings.Snapshot()
			if err != nil || snap.Configured || snap.Scope.Enabled || snap.Provider.APIKey != "" {
				t.Fatal("old saved provider can resurrect", err)
			}
			if o.app.ai.proactive.enabled {
				t.Fatal("provider replacement kept active scope")
			}
		})
	}
}
func TestPersistentAIDurableDisableAndDiskMismatch(t *testing.T) {
	for _, action := range []string{"disable", "disk-change"} {
		t.Run(action, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			settings, err := aiconfig.New(dir, "manager-fixture", "tls")
			if err != nil {
				t.Fatal(err)
			}
			if err = o.app.configurePersistentAI(settings, true); err != nil {
				t.Fatal(err)
			}
			status, _ := savePersistentFixture(t, o, csrf, "http://127.0.0.1:11434/v1", "", false)
			if status != 200 {
				t.Fatal(status)
			}
			source.now = time.Now().UTC()
			proactiveEnable(t, o, csrf, source.inputs[0].DeviceID)
			if action == "disable" {
				v := proactiveSettings(t, o)
				body := map[string]any{"expectedRevision": v["revision"], "configRevision": v["configRevision"], "enabled": false, "deviceIds": []string{}, "approvedBaseURL": "", "approvedModel": "", "dataScope": "health-summary-v1", "acknowledgeData": false}
				res, _ := o.call(t, "POST", "/api/ai/proactive", body, csrf, nil)
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode)
				}
				fresh, err := aiconfig.New(dir, "manager-fixture", "tls")
				if err != nil {
					t.Fatal(err)
				}
				snap, err := fresh.Snapshot()
				if err != nil || snap.Scope.Enabled {
					t.Fatal("disable lost on restart", err)
				}
			} else {
				seedProactiveIncident(t, o, source)
				path := filepath.Join(dir, aiconfig.SettingsFile)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, ' ')
				if err = os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				calls := 0
				o.app.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
					calls++
					return []byte(proactiveFindings), nil
				}})
				if err = o.app.runProactiveAI(context.Background(), o.app.health); err != nil || calls != 0 || o.app.ai.proactive.enabled {
					t.Fatal("changed protected settings allowed export", err, calls)
				}
			}
		})
	}
}

func TestPersistentAIActualStoreReopenConsumesInterruptedAndChecksAuthority(t *testing.T) {
	for _, mode := range []string{"interrupted", "revoked", "expired"} {
		t.Run(mode, func(t *testing.T) {
			o, source := investigationsFixture(t)
			_, session := o.login(t)
			csrf := session["csrfToken"].(string)
			id := source.inputs[0].DeviceID
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(dir, "operator.db")
			db, err := store.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			o.app.store = db
			o.app.health.store = db
			settings, err := aiconfig.New(dir, "manager-fixture", "tls")
			if err != nil {
				t.Fatal(err)
			}
			if err = o.app.configurePersistentAI(settings, true); err != nil {
				t.Fatal(err)
			}
			status, _ := savePersistentFixture(t, o, csrf, "http://127.0.0.1:11434/v1", "", false)
			if status != 200 {
				t.Fatal(status)
			}
			source.now = time.Now().UTC()
			proactiveEnable(t, o, csrf, id)
			seedProactiveIncident(t, o, source)
			state, err := db.HealthState(context.Background(), id)
			if err != nil || len(state.Incidents) != 1 {
				t.Fatal(err)
			}
			if mode == "interrupted" {
				claim, err := db.ClaimHealthAnalysis(context.Background(), id, state.Incidents[0].ID, o.app.ai.proactive.revision, o.app.ai.proactive.enabledAt, source.now)
				if err != nil || claim == nil {
					t.Fatal("claim not committed", err)
				}
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			reopenedDB, err := store.Open(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer reopenedDB.Close()
			reopenedSettings, err := aiconfig.New(dir, "manager-fixture", "tls")
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := New(reopenedDB, 8787, t.TempDir(), model.Device{})
			if err != nil {
				t.Fatal(err)
			}
			if err = fresh.configurePersistentAI(reopenedSettings, true); err != nil {
				t.Fatal(err)
			}
			fresh.health = &healthMonitor{store: reopenedDB, source: source}
			calls := 0
			fresh.ai.service = analysis.NewService(proactiveFake{call: func(context.Context, analysis.ProviderRequest) ([]byte, error) {
				calls++
				return []byte(proactiveFindings), nil
			}})
			if mode == "revoked" {
				source.inputs[0].Authorized = false
			}
			if mode == "expired" {
				source.inputs[0].AuthorityUntil = source.now
			}
			if err = fresh.runProactiveAI(context.Background(), fresh.health); err != nil || calls != 0 {
				t.Fatal("restart bypassed consumed claim or current authority", err, calls)
			}
			records, err := reopenedDB.HealthAnalyses(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "interrupted" {
				if len(records) != 1 || records[state.Incidents[0].ID].Status != "interrupted" {
					t.Fatal(records)
				}
			} else if len(records) != 0 {
				t.Fatal("unauthorized restoration created an attempt", records)
			}
		})
	}
}
