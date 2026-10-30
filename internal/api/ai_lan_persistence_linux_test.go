//go:build linux

package api

import (
	"localrmm/internal/aiconfig"
	"localrmm/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLANProviderForgetsPreviousPersistentProviderAndScope(t *testing.T) {
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
		t.Fatal("persistent setup", status)
	}
	source.now = time.Now().UTC()
	proactiveEnable(t, o, csrf, source.inputs[0].DeviceID)
	res, v := o.call(t, "POST", "/api/ai/config/lan", lanBody(o.app.ai.config.Revision), csrf, nil)
	if res.StatusCode != 200 || v["lanMode"] != true || v["storage"] != "memory-only" {
		t.Fatal("LAN replacement", res.StatusCode, v)
	}
	snap, err := settings.Snapshot()
	if err != nil || snap.Configured || snap.Scope.Enabled || o.app.ai.proactive.enabled {
		t.Fatal("old provider or scope survived", err)
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
	if fresh.ai.config.Configured || fresh.ai.config.LANMode || fresh.ai.proactive.enabled {
		t.Fatal("LAN resurrected on restart")
	}
}

func TestLANProviderFailsClosedOnPersistentFenceMismatch(t *testing.T) {
	o, _ := investigationsFixture(t)
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
	path := filepath.Join(dir, aiconfig.SettingsFile)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte(" ")); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	res, _ := o.call(t, "POST", "/api/ai/config/lan", lanBody(o.app.ai.config.Revision), csrf, nil)
	if res.StatusCode != 503 {
		t.Fatal("unsafe switch succeeded", res.StatusCode)
	}
	res, _ = o.call(t, "GET", "/api/ai/config", nil, "", nil)
	if res.StatusCode != 503 {
		t.Fatal("uncertain storage did not block read/export", res.StatusCode)
	}
}
