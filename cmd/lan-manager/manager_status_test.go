//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/managerstatus"
	"localrmm/internal/operatorauth"
	"localrmm/internal/store"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func diagnosticRequest(p *prepared, m lanconfig.Material, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, m.Config.OperatorOrigin+path, bytes.NewBufferString(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if m.Config.Profile == lanconfig.TLS {
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", m.Config.OperatorOrigin)
	}
	if token != "" {
		name := "__Host-tracebolt-session"
		if m.Config.Profile == lanconfig.HTTPTest {
			name = "tracebolt-http-test-session"
		}
		r.AddCookie(&http.Cookie{Name: name, Value: token})
	}
	w := httptest.NewRecorder()
	p.operator.ServeHTTP(w, r)
	return w
}

func TestManagerDiagnosticsRealStoresLivenessFailureAndRestart(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, _, _, _ := fixture(t, profile)
			p, err := prepare(m)
			if err != nil {
				t.Fatal("runtime preparation failed")
			}
			defer p.close()
			if p.diagnostics.monitor.Snapshot().Ready {
				t.Fatal("constructed process falsely ready")
			}
			if w := diagnosticRequest(p, m, "GET", "/livez", "", ""); w.Code != 200 {
				t.Fatal("minimal process liveness unavailable")
			}
			if w := diagnosticRequest(p, m, "GET", "/api/manager/readiness", "", ""); w.Code != 401 {
				t.Fatal("real manager diagnostics are public")
			}
			login := diagnosticRequest(p, m, "POST", "/api/auth/login", `{"password":"fixture-password-only"}`, "")
			if login.Code != 200 || len(login.Result().Cookies()) != 1 {
				t.Fatal("runtime fixture login failed")
			}
			token := login.Result().Cookies()[0].Value
			if err = p.diagnostics.monitor.Refresh(context.Background()); err != nil {
				t.Fatal("real-store diagnostic sample failed")
			}
			if w := diagnosticRequest(p, m, "GET", "/api/manager/readiness", "", token); w.Code != 200 {
				t.Fatal("real validated stores did not establish readiness")
			}
			metrics := diagnosticRequest(p, m, "GET", "/api/manager/metrics", "", token)
			var view managerstatus.Metrics
			if metrics.Code != 200 || json.Unmarshal(metrics.Body.Bytes(), &view) != nil || !view.Snapshot.Ready || view.HTTP[0].Requests < 3 {
				t.Fatal("real operational metrics absent")
			}
			p.close()
			_ = p.diagnostics.monitor.Refresh(context.Background())
			if w := diagnosticRequest(p, m, "GET", "/api/manager/readiness", "", token); w.Code != 503 {
				t.Fatal("closed authority stores stayed ready")
			}
			if w := diagnosticRequest(p, m, "GET", "/livez", "", ""); w.Code != 200 {
				t.Fatal("failed database changed process liveness")
			}
			// The reserved zero-only operational canary must not block ordinary
			// same-profile restart or reset any existing durable identity marker.
			restarted, err := prepare(m)
			if err != nil {
				t.Fatal("operational probe sidecar broke restart")
			}
			defer restarted.close()
			if err = restarted.diagnostics.monitor.Refresh(context.Background()); err != nil || !restarted.diagnostics.monitor.Snapshot().Ready {
				t.Fatal("restart diagnostic sample failed")
			}
		})
	}
}

func TestManagerDiagnosticsObservedMaintenanceDoesNotUseWarningSilence(t *testing.T) {
	now := time.Now().UTC()
	worker, err := managerstatus.NewWorker(time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal("worker fixture rejected")
	}
	worker.Start()
	observer := maintenanceObserver(worker)
	ticks := make(chan time.Time, 3)
	for i := 0; i < 3; i++ {
		ticks <- now
	}
	close(ticks)
	calls, warnings := 0, 0
	err = windowsEventMaintenanceLoopObserved(context.Background(), func(ctx context.Context, _ time.Time) error {
		if worker.Check(context.Background()).Work.Used != 1 {
			t.Fatal("actual in-flight step not observed")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 500*time.Millisecond {
			t.Fatal("maintenance observation removed deadline")
		}
		calls++
		now = now.Add(time.Second)
		switch calls {
		case 1:
			return enrollmentstore.ErrBusy
		case 2:
			return errors.New("private-source-error-sentinel")
		default:
			return nil
		}
	}, func() time.Time { return now }, ticks, func() { warnings++ }, observer)
	got := worker.Check(context.Background())
	if err != nil || calls != 3 || warnings != 1 || got.State != managerstatus.OK || got.Work.Completed != 3 || got.Work.Failed != 2 || got.Work.LastSucceededUnixMillis != now.UnixMilli() {
		t.Fatal("actual failed/recovered steps not recorded")
	}
	now = now.Add(7 * time.Second)
	if worker.Check(context.Background()).State != managerstatus.Stale {
		t.Fatal("stalled loop inferred healthy from no warning")
	}
	worker.Stop()
	if worker.Check(context.Background()).State != managerstatus.Stopped {
		t.Fatal("terminated maintenance inferred healthy")
	}
}

func TestManagerDiagnosticsServerTLSValidityIsNotProcessUptime(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.TLS)
	if err := lanstore.PrepareProfileDirectory(m.Config.StateDirectory, m.Config.Profile); err != nil {
		t.Fatal("fixture profile failed")
	}
	trust, err := lanstore.Open(filepath.Join(m.Config.StateDirectory, "agents.db"))
	if err != nil {
		t.Fatal("fixture trust failed")
	}
	defer trust.Close()
	application, err := store.Open(filepath.Join(m.Config.StateDirectory, "operator.db"))
	if err != nil {
		t.Fatal("fixture application failed")
	}
	defer application.Close()
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: m.PasswordHash})
	if err != nil {
		t.Fatal("fixture auth failed")
	}
	leaf, err := x509.ParseCertificate(m.Server.Certificate[0])
	if err != nil {
		t.Fatal("fixture certificate failed")
	}
	now := leaf.NotBefore
	diagnostics, err := newManagerDiagnostics(m, managerDiagnosticSources{Application: application, Trust: trust, Auth: auth}, func() time.Time { return now })
	if err != nil {
		t.Fatal("diagnostic construction failed")
	}
	_ = diagnostics.monitor.Refresh(context.Background())
	if !diagnostics.monitor.Snapshot().Ready {
		t.Fatal("exact server NotBefore rejected")
	}
	now = leaf.NotAfter
	_ = diagnostics.monitor.Refresh(context.Background())
	view := diagnostics.monitor.Snapshot()
	found := false
	for _, component := range view.Components {
		if component.Component == managerstatus.ServerTLS {
			found = true
			if component.State != managerstatus.Expired {
				t.Fatal("expired server certificate classified incorrectly")
			}
		}
	}
	if view.Ready || !found {
		t.Fatal("expired server TLS ignored because process was running")
	}
}

func TestManagerDiagnosticsProtectedStoreRejectsReplacementAndMode(t *testing.T) {
	for _, kind := range []string{"replace", "public", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal("fixture private directory failed")
			}
			path := filepath.Join(dir, "operator.db")
			if err := os.WriteFile(path, []byte("known-private-fixture"), 0600); err != nil {
				t.Fatal("fixture failed")
			}
			calls := 0
			probe, err := protectedManagerStoreProbe(path, func(context.Context) managerstatus.ProbeResult {
				calls++
				return managerstatus.ProbeResult{State: managerstatus.OK}
			})
			if err != nil {
				t.Fatal("valid protected fixture rejected")
			}
			if probe(context.Background()).State != managerstatus.OK || calls != 1 {
				t.Fatal("valid probe blocked")
			}
			switch kind {
			case "replace":
				if err = os.Rename(path, path+"-old"); err == nil {
					err = os.WriteFile(path, []byte("replacement"), 0600)
				}
			case "public":
				err = os.Chmod(path, 0644)
			case "symlink":
				if err = os.Rename(path, path+"-old"); err == nil {
					err = os.Symlink(path+"-old", path)
				}
			case "hardlink":
				err = os.Link(path, path+"-alias")
			}
			if err != nil {
				t.Fatal("fixture alteration failed")
			}
			if probe(context.Background()).State != managerstatus.Invalid || calls != 1 {
				t.Fatal("unsafe/replaced store was queried or adopted")
			}
		})
	}
}
