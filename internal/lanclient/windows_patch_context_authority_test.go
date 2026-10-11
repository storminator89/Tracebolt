//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowspatchcontext"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The reload seam substitutes native Windows material loading only. These tests
// use actual protected disposable config/ready bytes and the production guard.
func windowsActivatedMaterialFixture(t *testing.T) (Material, func(string) (Material, error), func(string)) {
	t.Helper()
	m := windowsMaterialFixture(t, "http-test")
	m.configPath = filepath.Join(filepath.Dir(m.config.StateDirectory), "agent.json")
	raw, _ := json.Marshal(m.config)
	configHash := sha256.Sum256(raw)
	certHash := sha256.Sum256(m.certificate.Certificate[0])
	ready, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(configHash[:]), "certificateHash": hex.EncodeToString(certHash[:]), "serverAuthenticated": false})
	if e := os.WriteFile(m.configPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(m.configPath), "ready.json")
	if e := os.WriteFile(path, ready, 0600); e != nil {
		t.Fatal(e)
	}
	current := m
	var loadErr error
	reload := func(got string) (Material, error) {
		if got != m.configPath {
			t.Fatal("reload path")
		}
		return current, loadErr
	}
	change := func(kind string) {
		switch kind {
		case "identity-replaced":
			current.binding = strings.Repeat("0", 64)
		case "config-replaced":
			updated := m.config
			updated.AgentID = "agent_" + strings.Repeat("2", 32)
			b, _ := json.Marshal(updated)
			if e := os.WriteFile(m.configPath, b, 0600); e != nil {
				t.Fatal(e)
			}
		case "ready-removed":
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
		case "ready-replaced":
			if e := os.WriteFile(path, []byte(`{}`), 0600); e != nil {
				t.Fatal(e)
			}
		case "load-denied":
			loadErr = ErrConfiguration
		default:
			t.Fatal(kind)
		}
	}
	if !currentWindowsContextMaterial(m, reload) {
		t.Fatal("valid activated fixture rejected")
	}
	return m, reload, change
}
func TestWindowsPatchContextCurrentIdentitySuppressesPendingRetry(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed", "ready-replaced", "load-denied"} {
		t.Run(kind, func(t *testing.T) {
			m, reload, change := windowsActivatedMaterialFixture(t)
			state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
			if e != nil {
				t.Fatal(e)
			}
			defer state.Close()
			c := patchConsentFixture(m)
			calls := 0
			var bodies [][]byte
			var sent frame
			send := func(req *http.Request) (*http.Response, error) {
				raw, _ := io.ReadAll(req.Body)
				bodies = append(bodies, bytes.Clone(raw))
				sent = frame{}
				if json.Unmarshal(raw, &sent) != nil {
					t.Fatal("frame")
				}
				return nil, errors.New("fixture offline")
			}
			read := func() (windowspatchcontext.Consent, bool) { return c, currentWindowsContextMaterial(m, reload) }
			_, e = runPatchOnlyWithAuthority(context.Background(), m, state, send, read, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
				calls++
				return patchSourceFixture(ctx, r)
			}, func() bool { return currentWindowsContextMaterial(m, reload) })
			if !errors.Is(e, ErrTransport) || sent.WindowsPatchContext == nil {
				t.Fatal("missing pending", e)
			}
			first, pendingErr := state.Pending()
			if pendingErr != nil || first == nil {
				t.Fatal("pending fixture", pendingErr)
			}
			change(kind)
			report, e := runPatchOnlyWithAuthority(context.Background(), m, state, send, read, func(context.Context, windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
				t.Fatal("stale identity recollected patch")
				return windowspatchcontext.Snapshot{}, nil
			}, func() bool { return currentWindowsContextMaterial(m, reload) })
			retained, pendingErr := state.Pending()
			if !errors.Is(e, ErrState) || report.DiscardedUnconsented || report.RetriedPending || calls != 1 || len(bodies) != 1 || pendingErr != nil || retained == nil || retained.Digest != first.Digest || !bytes.Equal(retained.Body(), first.Body()) {
				t.Fatal("stale private patch retried", e, report)
			}
		})
	}
}
func TestWindowsPatchContextCurrentIdentityAfterCaptureAndBeforeSend(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed"} {
		for _, phase := range []string{"after-capture", "before-send"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				m, reload, change := windowsActivatedMaterialFixture(t)
				state, e := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
				if e != nil {
					t.Fatal(e)
				}
				defer state.Close()
				c := patchConsentFixture(m)
				reads := 0
				sent := false
				_, e = runPatchOnlyWithAuthority(context.Background(), m, state, func(*http.Request) (*http.Response, error) { sent = true; return nil, nil }, func() (windowspatchcontext.Consent, bool) {
					reads++
					if phase == "before-send" && reads == 4 {
						change(kind)
					}
					return c, currentWindowsContextMaterial(m, reload)
				}, func(ctx context.Context, r windowspatchcontext.Request) (windowspatchcontext.Snapshot, error) {
					s, e := patchSourceFixture(ctx, r)
					if phase == "after-capture" {
						change(kind)
					}
					return s, e
				}, func() bool { return currentWindowsContextMaterial(m, reload) })
				if !errors.Is(e, ErrState) || sent {
					t.Fatal("stale identity sent", e, reads)
				}
			})
		}
	}
}
