//go:build linux

package enrollmentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanclient"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func claimServiceFixture(t *testing.T, profile string) *clientFixture {
	t.Helper()
	f := newClientFixture(t, profile)
	f.autoApprove = false
	options := f.options()
	options.ClaimOnly = true
	result, err := Run(context.Background(), f.bootstrap, options)
	if err != nil || !result.Pending || result.ConfigPath != "" || result.ServerAuthenticated != (profile == "tls") {
		t.Fatal("claim-only result", err)
	}
	for _, name := range []string{"agent.json", "ready.json", "telemetry", "agent-key.pem", "agent-cert.pem"} {
		if _, err := os.Lstat(filepath.Join(f.state, name)); !os.IsNotExist(err) {
			t.Fatal("preactivation artifact exists", name)
		}
	}
	raw, err := os.ReadFile(filepath.Join(f.state, serviceMarkerName))
	if err != nil || strings.Contains(string(raw), f.secret) {
		t.Fatal("marker absent or includes invitation")
	}
	return f
}
func fixtureApproveService(t *testing.T, f *clientFixture) {
	t.Helper()
	v, err := f.service.Snapshots(context.Background())
	if err != nil || len(v) != 1 {
		t.Fatal("snapshot", err)
	}
	if _, err = f.service.Approve(context.Background(), v[0].InvitationID, testID("request", 900), v[0].Claim.KeyFingerprint, v[0].Revision); err != nil {
		t.Fatal("approve", err)
	}
}
func changeServiceMarker(t *testing.T, f *clientFixture, change func(*serviceEnrollment)) {
	t.Helper()
	st, err := openExistingStore(f.state)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, err := st.Read(serviceMarkerName)
	if err != nil {
		t.Fatal(err)
	}
	var m serviceEnrollment
	if strictJSON(raw, &m) != nil {
		t.Fatal("marker parse")
	}
	change(&m)
	raw, err = json.Marshal(m)
	if err != nil || st.Write(serviceMarkerName, raw) != nil {
		t.Fatal("fixture marker change")
	}
}
func TestPendingServiceClaimThenResumeWithoutInvitation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := claimServiceFixture(t, profile)
			before, err := os.ReadFile(filepath.Join(f.state, "ledger.json"))
			if err != nil {
				t.Fatal(err)
			}
			view, err := InspectService(f.bootstrap, f.state, profile == "http-test")
			if err != nil || view.Ready {
				t.Fatal("pending inspector", err)
			}
			after, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
			if string(before) != string(after) {
				t.Fatal("inspector wrote ledger")
			}
			fixtureApproveService(t, f)
			result, err := ResumeService(context.Background(), f.bootstrap, f.state, profile == "http-test", nil)
			if err != nil || result.Pending || result.ConfigPath == "" {
				t.Fatal("service resume", err)
			}
			ready, err := MarkServiceReady(f.bootstrap, f.state, profile == "http-test")
			if err != nil || !ready.Ready {
				t.Fatal("ready marker", err)
			}
			// Complete ready resumes offline after the original pending deadline.
			changeServiceMarker(t, f, func(m *serviceEnrollment) { m.ClaimAt = time.Now().Unix() - 10; m.DeadlineAt = time.Now().Unix() - 1 })
			f.server.Close()
			ready, err = InspectService(f.bootstrap, f.state, profile == "http-test")
			if err != nil || !ready.Ready {
				t.Fatal("ready boot required live manager or pending deadline", err)
			}
		})
	}
}
func TestPendingServiceLostClaimAcknowledgementDoesNotPublishMarker(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.autoApprove = false
	f.dropClaimAfter = true
	options := f.options()
	options.ClaimOnly = true
	options.Timeout = time.Second
	result, err := Run(context.Background(), f.bootstrap, options)
	if err == nil || result.Pending {
		t.Fatal("uncertain claim became service-ready")
	}
	if _, err := os.Lstat(filepath.Join(f.state, serviceMarkerName)); !os.IsNotExist(err) {
		t.Fatal("unconfirmed marker published")
	}
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrState) {
		t.Fatal("unconfirmed service resume", err)
	}
}
func TestPendingServiceResumeMissingIdentityAndMarkerNeverCreates(t *testing.T) {
	f := newClientFixture(t, "http-test")
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := ResumeService(context.Background(), f.bootstrap, missing, true, nil); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("missing directory recreated")
	}
	for _, name := range []string{"ledger.json", "enrollment.lock", serviceMarkerName} {
		t.Run(name, func(t *testing.T) {
			fresh := claimServiceFixture(t, "http-test")
			if os.Remove(filepath.Join(fresh.state, name)) != nil {
				t.Fatal("fixture remove")
			}
			if _, err := ResumeService(context.Background(), fresh.bootstrap, fresh.state, true, nil); !errors.Is(err, ErrState) {
				t.Fatal("missing state accepted", err)
			}
			if _, err := os.Lstat(filepath.Join(fresh.state, name)); !os.IsNotExist(err) {
				t.Fatal("missing state recreated")
			}
		})
	}
}
func TestPendingServiceDeadlineIsBoundedAndLatched(t *testing.T) {
	f := claimServiceFixture(t, "tls")
	changeServiceMarker(t, f, func(m *serviceEnrollment) { m.ClaimAt = time.Now().Unix() - 10; m.DeadlineAt = time.Now().Unix() - 1 })
	f.mu.Lock()
	count := len(f.requests)
	f.mu.Unlock()
	if _, err := InspectService(f.bootstrap, f.state, false); !errors.Is(err, ErrServiceDeadline) {
		t.Fatal("deadline ignored", err)
	}
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrServiceDeadline) {
		t.Fatal("resume after deadline", err)
	}
	f.mu.Lock()
	if len(f.requests) != count {
		t.Error("network request after local deadline")
	}
	f.mu.Unlock()
	raw, _ := os.ReadFile(filepath.Join(f.state, serviceMarkerName))
	var m serviceEnrollment
	if strictJSON(raw, &m) != nil || !m.DeadlineStopped {
		t.Fatal("deadline stop not durable")
	}
	changeServiceMarker(t, f, func(m *serviceEnrollment) { m.ClaimAt = time.Now().Unix(); m.DeadlineAt = time.Now().Unix() + 60 })
	if _, err := InspectService(f.bootstrap, f.state, false); !errors.Is(err, ErrServiceDeadline) {
		t.Fatal("latched stop reset")
	}
}
func TestPendingServiceObservedTerminalLatchesAcrossRestart(t *testing.T) {
	for _, terminal := range []enrollmentstate.State{enrollmentstate.Canceled, enrollmentstate.Rejected} {
		t.Run(string(terminal), func(t *testing.T) {
			f := claimServiceFixture(t, "tls")
			v, err := f.service.Snapshots(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.Terminate(context.Background(), v[0].InvitationID, testID("request", 901), v[0].Revision, terminal); err != nil {
				t.Fatal(err)
			}
			if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrTerminal) {
				t.Fatal("terminal resume", err)
			}
			f.server.Close()
			if _, err := InspectService(f.bootstrap, f.state, false); !errors.Is(err, ErrTerminal) {
				t.Fatal("terminal marker did not win offline", err)
			}
		})
	}
}
func TestPendingServiceReadyObservedAndInitializedStateAreNotRecreated(t *testing.T) {
	for _, name := range []string{"ready.json", "telemetry"} {
		t.Run(name, func(t *testing.T) {
			f := claimServiceFixture(t, "http-test")
			fixtureApproveService(t, f)
			if _, err := ResumeService(context.Background(), f.bootstrap, f.state, true, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := MarkServiceReady(f.bootstrap, f.state, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.state, name)
			if os.Rename(path, filepath.Join(t.TempDir(), "retained-"+name)) != nil {
				t.Fatal("fixture rename")
			}
			if _, err := InspectService(f.bootstrap, f.state, true); !errors.Is(err, ErrState) {
				t.Fatal("missing ready/counter accepted", err)
			}
			if _, err := ResumeService(context.Background(), f.bootstrap, f.state, true, nil); !errors.Is(err, ErrState) {
				t.Fatal("direct resume repaired missing ready/counter", err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("missing state recreated")
			}
		})
	}
}
func TestPendingServiceHTTPAcknowledgementAndMarkerBindingsFailClosed(t *testing.T) {
	f := claimServiceFixture(t, "http-test")
	if _, err := InspectService(f.bootstrap, f.state, false); !errors.Is(err, ErrBootstrap) {
		t.Fatal("missing HTTP acknowledgement")
	}
	for _, kind := range []string{"mode", "key", "bootstrap", "claim", "deadline", "auth"} {
		t.Run(kind, func(t *testing.T) {
			fresh := claimServiceFixture(t, "http-test")
			changeServiceMarker(t, fresh, func(m *serviceEnrollment) {
				switch kind {
				case "mode":
					m.Mode = "ready-only-v1"
				case "key":
					m.KeyFingerprint = strings.Repeat("f", 64)
				case "bootstrap":
					m.BootstrapHash = strings.Repeat("e", 64)
				case "claim":
					m.ClaimID = testID("claim", 999)
				case "deadline":
					m.DeadlineAt = m.ClaimAt + enrollmentstate.MaxPendingTTL + 1
				case "auth":
					m.ServerAuthenticated = true
				}
			})
			if _, err := InspectService(fresh.bootstrap, fresh.state, true); !errors.Is(err, ErrState) {
				t.Fatal("marker mismatch accepted", err)
			}
		})
	}
}

func TestPendingServiceDelayedResponsesCannotCrossLocalDeadline(t *testing.T) {
	for _, route := range []string{"status", "credential", "activate", "challenge-activation"} {
		t.Run(route, func(t *testing.T) {
			f := newClientFixture(t, "tls")
			f.autoApprove = false
			deadline := time.Now().Unix() + 3
			original := f.server.Config.Handler
			var armed, delayed atomic.Bool
			var entered atomic.Int32
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered.Add(1)
				target := strings.HasSuffix(r.URL.Path, "/"+route)
				if route == "challenge-activation" && strings.HasSuffix(r.URL.Path, "/challenge") {
					raw, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(raw))
					target = bytes.Contains(raw, []byte(`"purpose":"activation"`))
				}
				recorded := httptest.NewRecorder()
				original.ServeHTTP(recorded, r)
				if armed.Load() && target && delayed.CompareAndSwap(false, true) {
					time.Sleep(time.Until(time.Unix(deadline, 0)) + 20*time.Millisecond)
				}
				raw := recorded.Body.Bytes()
				var fields map[string]json.RawMessage
				if json.Unmarshal(raw, &fields) == nil && fields["deadlineAt"] != nil {
					fields["deadlineAt"], _ = json.Marshal(deadline)
					raw, _ = json.Marshal(fields)
				}
				for key, values := range recorded.Header() {
					for _, v := range values {
						w.Header().Add(key, v)
					}
				}
				w.WriteHeader(recorded.Code)
				w.Write(raw)
			})
			options := f.options()
			options.ClaimOnly = true
			if result, err := Run(context.Background(), f.bootstrap, options); err != nil || !result.Pending {
				t.Fatal("coherent short deadline claim", err)
			}
			fixtureApproveService(t, f)
			armed.Store(true)
			_, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil)
			if !delayed.Load() {
				t.Fatal("target route never reached", route)
			}
			if !errors.Is(err, ErrServiceDeadline) {
				t.Fatal("late response did not stop", err)
			}
			raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
			var l ledger
			if strictJSON(raw, &l) != nil || l.Activated || l.SenderInitializationStarted {
				t.Fatal("late response activated/initialized sender")
			}
			if _, err := os.Lstat(filepath.Join(f.state, "ready.json")); !os.IsNotExist(err) {
				t.Fatal("late response published ready")
			}
			before := entered.Load()
			if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrServiceDeadline) {
				t.Fatal("restart reset deadline", err)
			}
			if entered.Load() != before {
				t.Error("restart contacted manager past deadline")
			}
		})
	}
}

func TestPendingServiceMatchingActivatedStatusAfterDeadlineCannotPublish(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.autoApprove = false
	deadline := time.Now().Unix() + 4
	original := f.server.Config.Handler
	var armed, delayed, sawActivated atomic.Bool
	var entered atomic.Int32
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		recorded := httptest.NewRecorder()
		original.ServeHTTP(recorded, r)
		raw := recorded.Body.Bytes()
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) == nil && fields["deadlineAt"] != nil {
			fields["deadlineAt"], _ = json.Marshal(deadline)
			raw, _ = json.Marshal(fields)
		}
		if armed.Load() && strings.HasSuffix(r.URL.Path, "/status") && delayed.CompareAndSwap(false, true) {
			var snapshot enrollmentstate.Snapshot
			if json.Unmarshal(raw, &snapshot) == nil && snapshot.State == enrollmentstate.Activated {
				sawActivated.Store(true)
			}
			time.Sleep(time.Until(time.Unix(deadline, 0)) + 20*time.Millisecond)
		}
		for key, values := range recorded.Header() {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(recorded.Code)
		w.Write(raw)
	})
	options := f.options()
	options.ClaimOnly = true
	if result, err := Run(context.Background(), f.bootstrap, options); err != nil || !result.Pending {
		t.Fatal("short deadline claim", err)
	}
	fixtureApproveService(t, f)
	// Stop at the precise durable pre-promotion state: activation has committed
	// remotely using our saved request ID, but local Activated is still false.
	st, err := openExistingStore(f.state)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := validateBootstrap(f.bootstrap, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := &session{&sessionData{store: st, opts: Options{StateDirectory: f.state, ResumeOnly: true}, trust: trust}}
	if err = s.load(f.bootstrap); err != nil {
		t.Fatal(err)
	}
	s.trust.KeyFingerprint = fingerprint(s.publicDER)
	s.trust.ComparisonCode, err = enrollmentcrypto.ComparisonCode(f.bootstrap.ManagerInstanceID, f.bootstrap.InvitationID, s.l.ClaimID, s.trust.KeyFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.loadService(true); err != nil {
		t.Fatal(err)
	}
	client, err := lanclient.NewBootstrapHTTPClient(f.bootstrap.EnrollmentOrigin, "tls", []byte(f.bootstrap.ServerCAPEM))
	if err != nil {
		t.Fatal(err)
	}
	s.wire = &wireClient{client: client, origin: f.bootstrap.EnrollmentOrigin}
	snapshot, err := s.status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.acceptSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = s.recordServiceSnapshot(snapshot, false); err != nil {
		t.Fatal(err)
	}
	if err = s.credential(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err = s.activate(context.Background()); err != nil || s.l.Activated || !s.l.ActivationAttempted {
		t.Fatal("activation attempt fixture", err)
	}
	activated, err := f.service.Snapshots(context.Background())
	if err != nil || len(activated) != 1 || activated[0].State != enrollmentstate.Activated || activated[0].Activation.RequestID != s.l.ActivationRequestID {
		t.Fatal("manager not bound Activated")
	}
	st.Close()
	client.CloseIdleConnections()
	clear(s.key)
	armed.Store(true)
	_, err = ResumeService(context.Background(), f.bootstrap, f.state, false, nil)
	if !errors.Is(err, ErrServiceDeadline) || !delayed.Load() || !sawActivated.Load() {
		t.Fatal("late matching Activated status did not hit manual-only stop", err)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var l ledger
	if strictJSON(raw, &l) != nil || l.Activated || l.SenderInitializationStarted {
		t.Fatal("late Activated status initialized local sender")
	}
	if _, err := os.Lstat(filepath.Join(f.state, "ready.json")); !os.IsNotExist(err) {
		t.Fatal("late Activated response published ready")
	}
	before := entered.Load()
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrServiceDeadline) {
		t.Fatal("restart reset manual-only deadline", err)
	}
	if entered.Load() != before {
		t.Fatal("restart contacted manager")
	}
}

func TestPendingServiceJournaledPublicationRecoveryBoundaries(t *testing.T) {
	for _, phase := range []string{"pre-init", "pre-init-partial", "initialized-before-config", "intent-with-missing-domain", "unknown-write-temp"} {
		t.Run(phase, func(t *testing.T) {
			f := claimServiceFixture(t, "tls")
			fixtureApproveService(t, f)
			result, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			telemetryBytes, _ := os.ReadFile(filepath.Join(result.Config.StateDirectory, "state.json"))
			ledgerPath := filepath.Join(f.state, "ledger.json")
			raw, _ := os.ReadFile(ledgerPath)
			var l ledger
			if strictJSON(raw, &l) != nil {
				t.Fatal("fixture ledger")
			}
			backup := t.TempDir()
			preserve := func(name string) {
				t.Helper()
				if err := os.Rename(filepath.Join(f.state, name), filepath.Join(backup, name)); err != nil {
					t.Fatal("preserve fixture", name, err)
				}
			}
			switch phase {
			case "pre-init", "pre-init-partial":
				l.HandoffPrepared = false
				l.SenderInitializationStarted = false
				for _, name := range []string{"telemetry", "agent.json", "ready.json", "agent-cert.pem", "server-ca.pem"} {
					preserve(name)
				}
				if phase == "pre-init" {
					preserve("agent-key.pem")
				}
			case "initialized-before-config":
				l.HandoffPrepared = false
				preserve("agent.json")
				preserve("ready.json")
			case "intent-with-missing-domain":
				l.HandoffPrepared = false
				preserve("telemetry")
				preserve("agent.json")
				preserve("ready.json")
			case "unknown-write-temp":
				if os.WriteFile(filepath.Join(f.state, ".enrollment.tmp"), []byte("synthetic interrupted write"), 0600) != nil {
					t.Fatal("temp fixture")
				}
			}
			raw, _ = json.Marshal(ledgerDisk(*l.ledgerData))
			if os.WriteFile(ledgerPath, raw, 0600) != nil {
				t.Fatal("checkpoint fixture")
			}
			_, err = ResumeService(context.Background(), f.bootstrap, f.state, false, nil)
			if phase == "intent-with-missing-domain" || phase == "unknown-write-temp" {
				if !errors.Is(err, ErrState) {
					t.Fatal("unsafe phase resumed", phase, err)
				}
				if phase == "intent-with-missing-domain" {
					if _, err := os.Lstat(filepath.Join(f.state, "telemetry")); !os.IsNotExist(err) {
						t.Fatal("initialization intent recreated domain")
					}
				}
				return
			}
			if err != nil {
				t.Fatal("journaled phase did not resume", phase, err)
			}
			if ready, err := MarkServiceReady(f.bootstrap, f.state, false); err != nil || !ready.Ready {
				t.Fatal("recovered phase not ready", err)
			}
			if phase == "initialized-before-config" {
				after, _ := os.ReadFile(filepath.Join(result.Config.StateDirectory, "state.json"))
				if !bytes.Equal(telemetryBytes, after) {
					t.Fatal("existing initialized counter changed")
				}
			}
		})
	}
}

func TestPendingServiceClaimResponseAloneCannotCreateServiceMarker(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.autoApprove = false
	original := f.server.Config.Handler
	var claimed atomic.Bool
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/status") && claimed.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			w.Write([]byte(`{"error":"synthetic unavailable status"}`))
			return
		}
		original.ServeHTTP(w, r)
		if strings.HasSuffix(r.URL.Path, "/claim") {
			claimed.Store(true)
		}
	})
	options := f.options()
	options.ClaimOnly = true
	options.Timeout = time.Second
	if result, err := Run(context.Background(), f.bootstrap, options); err == nil || result.Pending {
		t.Fatal("claim response alone authorized service")
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var l ledger
	if strictJSON(raw, &l) != nil || !l.ClaimConfirmed {
		t.Fatal("fixture did not save successful claim response")
	}
	if _, err := os.Lstat(filepath.Join(f.state, serviceMarkerName)); !os.IsNotExist(err) {
		t.Fatal("marker published without successful bound status")
	}
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrState) {
		t.Fatal("service resumed without status marker", err)
	}
}
func TestPendingServiceObservedRevocationWinsOverCompletedReady(t *testing.T) {
	f := claimServiceFixture(t, "tls")
	fixtureApproveService(t, f)
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := MarkServiceReady(f.bootstrap, f.state, false); err != nil {
		t.Fatal(err)
	}
	records, err := f.service.Snapshots(context.Background())
	if err != nil || len(records) != 1 {
		t.Fatal(err)
	}
	if _, err = f.service.Terminate(context.Background(), records[0].InvitationID, testID("request", 902), records[0].Revision, enrollmentstate.Revoked); err != nil {
		t.Fatal(err)
	}
	// Explicit enrollment revalidation observes the terminal outcome. The normal
	// reporting loop deliberately does not add an implicit revocation poller.
	if _, err := ResumeService(context.Background(), f.bootstrap, f.state, false, nil); !errors.Is(err, ErrTerminal) {
		t.Fatal("observed revoke not terminal", err)
	}
	f.server.Close()
	if _, err := InspectService(f.bootstrap, f.state, false); !errors.Is(err, ErrTerminal) {
		t.Fatal("ready files overrode terminal latch", err)
	}
	if _, err := MarkServiceReady(f.bootstrap, f.state, false); !errors.Is(err, ErrTerminal) {
		t.Fatal("ready mark cleared terminal latch", err)
	}
}
