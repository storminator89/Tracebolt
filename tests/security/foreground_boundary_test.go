//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/agentloop"
	"localrmm/internal/api"
	"localrmm/internal/bundle"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Disposable, normally authenticated TLS fixture. No malformed keys or forged
// requests are used. Tests cancel at event boundaries instead of sleeping.
type foregroundBoundaryFixture struct {
	material lanclient.Material
	config   lanclient.Config
	binding  string
	registry *lantrust.Registry
	store    *lanstore.Store
}

func newForegroundBoundaryFixture(t *testing.T, wrap func(http.Handler) http.Handler) foregroundBoundaryFixture {
	t.Helper()
	dir := t.TempDir()
	ca := makeReviewCA(t)
	client, public := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Time{})
	serverCertificate, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
	state, err := lanstore.Open(filepath.Join(dir, "manager", "state.db"))
	if err != nil {
		t.Fatal("fixture store setup")
	}
	t.Cleanup(func() { state.Close() })
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, state)
	if err != nil {
		t.Fatal("fixture registry setup")
	}
	agent, err := registry.Approve(context.Background(), public, "Disposable foreground fixture")
	if err != nil {
		t.Fatal("fixture approval")
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := api.NewLANIngressHandler(registry, state, origin)
	if err != nil {
		t.Fatal("fixture ingress setup")
	}
	if wrap != nil {
		handler = wrap(handler)
	}
	server.Config.Handler = handler
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS, err = registry.TLSConfig(serverCertificate)
	if err != nil {
		t.Fatal("fixture TLS setup")
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	config := lanclient.Config{
		SchemaVersion: lanclient.ConfigVersion, Profile: "tls", ManagerOrigin: origin, AgentID: agent.ID,
		CertificateFile: filepath.Join(dir, "client.pem"), PrivateKeyFile: filepath.Join(dir, "client.key"),
		ServerCAFile: filepath.Join(dir, "ca.pem"), StateDirectory: filepath.Join(dir, "sender"),
	}
	key, err := x509.MarshalPKCS8PrivateKey(client.PrivateKey)
	if err != nil {
		t.Fatal("fixture key encoding")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer clear(key)
	defer clear(keyPEM)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal("fixture configuration encoding")
	}
	configPath := filepath.Join(dir, "config.json")
	for name, content := range map[string][]byte{config.CertificateFile: public, config.PrivateKeyFile: keyPEM, config.ServerCAFile: ca.pem, configPath: raw} {
		if os.WriteFile(name, content, 0600) != nil {
			t.Fatal("fixture protected file setup")
		}
	}
	material, err := lanclient.Load(configPath)
	if err != nil {
		t.Fatal("fixture material load")
	}
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.v1\n" + config.Profile + "\n" + config.ManagerOrigin + "\n" + lantrust.Fingerprint(client.Leaf) + "\n" + config.AgentID))
	return foregroundBoundaryFixture{material, config, hex.EncodeToString(sum[:]), registry, state}
}

func (f foregroundBoundaryFixture) openState(t *testing.T) *lanclientstate.State {
	t.Helper()
	state, err := lanclientstate.Open(f.config.StateDirectory, f.binding)
	if err != nil {
		t.Fatal("sender ledger did not reopen")
	}
	t.Cleanup(func() { state.Close() })
	return state
}

func foregroundOneResult(t *testing.T, f foregroundBoundaryFixture, phase agentloop.Phase) (agentloop.Summary, []agentloop.Event) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []agentloop.Event
	summary, err := lanclient.RunForeground(ctx, f.material, agentloop.MinInterval, func(event agentloop.Event) error {
		events = append(events, event)
		if event.Phase == phase {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || summary.Reason != agentloop.Cancelled || summary.Attempts != 1 {
		t.Fatal("foreground did not stop at the requested observation boundary")
	}
	return summary, events
}

func TestIndependentForegroundExpiredDeadlineIsClassified(t *testing.T) {
	f := newForegroundBoundaryFixture(t, nil)
	ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	summary, err := lanclient.RunForeground(ctx, f.material, agentloop.MinInterval, nil)
	if !errors.Is(err, context.DeadlineExceeded) || summary.Reason != agentloop.Deadline || summary.Attempts != 0 {
		t.Fatalf("expired deadline misclassified: reason=%s attempts=%d", summary.Reason, summary.Attempts)
	}
	if _, err := os.Stat(f.config.StateDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pre-cancelled foreground opened sender state")
	}
}

func TestIndependentForegroundRetainsLockThroughWaitingObserver(t *testing.T) {
	f := newForegroundBoundaryFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := false
	summary, err := lanclient.RunForeground(ctx, f.material, agentloop.MinInterval, func(event agentloop.Event) error {
		if event.Phase == agentloop.Waiting {
			waiting = true
			other, openErr := lanclientstate.Open(f.config.StateDirectory, f.binding)
			if other != nil {
				other.Close()
			}
			if !errors.Is(openErr, lanclientstate.ErrLocked) {
				t.Error("foreground released exclusive lock before wait")
			}
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || !waiting || summary.Attempts != 1 {
		t.Fatal("waiting boundary not exercised")
	}
	state := f.openState(t)
	if next, err := state.NextSequence(); err != nil || next != 2 {
		t.Fatal("acknowledgment sequence did not survive shutdown")
	}
}

func TestIndependentForegroundExactPendingRetryDoesNotRefreshReceipt(t *testing.T) {
	var mu sync.Mutex
	var requests [][]byte
	var receipts []lanstore.Receipt
	f := newForegroundBoundaryFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(io.LimitReader(r.Body, lanclient.MaxFrameBytes+1))
			if err != nil {
				t.Error("fixture request read")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			var receipt lanstore.Receipt
			if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &receipt) != nil {
				t.Error("fixture manager did not commit")
				return
			}
			mu.Lock()
			requests = append(requests, bytes.Clone(raw))
			receipts = append(receipts, receipt)
			first := len(requests) == 1
			mu.Unlock()
			if first {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error("fixture response loss")
					return
				}
				conn.Close()
				return
			}
			for key, values := range recorder.Header() {
				w.Header()[key] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
		})
	})
	if report, err := lanclient.Run(context.Background(), f.material); !errors.Is(err, lanclient.ErrTransport) || report.Sequence != 1 {
		t.Fatal("fixture did not leave an uncertain committed request")
	}
	_, events := foregroundOneResult(t, f, agentloop.Finished)
	if len(events) != 3 || events[1].Outcome != agentloop.Success || events[1].Metadata.Sequence != 1 || !events[1].Metadata.RetriedPending || !events[1].Metadata.Duplicate {
		t.Fatal("foreground did not acknowledge the exact pending request")
	}
	mu.Lock()
	same := len(requests) == 2 && bytes.Equal(requests[0], requests[1]) && receipts[0].ReceivedAt.Equal(receipts[1].ReceivedAt) && receipts[0].CollectedAt.Equal(receipts[1].CollectedAt)
	first := receipts[0]
	mu.Unlock()
	if !same {
		t.Fatal("retry changed request bytes or manager receipt freshness")
	}
	devices, err := f.store.Devices(context.Background(), f.registry.List(), time.Now())
	if err != nil || len(devices) != 1 || !devices[0].LastSeen.Equal(first.CollectedAt) {
		t.Fatal("retry refreshed manager observation freshness")
	}
	state := f.openState(t)
	pending, err := state.Pending()
	if err != nil || pending != nil {
		t.Fatal("acknowledged pending request remained staged")
	}
}

func TestIndependentForegroundDiscardsStaleWithoutRewritingOldSample(t *testing.T) {
	f := newForegroundBoundaryFixture(t, nil)
	at := time.Now().UTC().Add(-3 * time.Minute)
	d := localRoleFixture()
	d.OS = "Disposable stale sample marker"
	d.LastSeen, d.CPU.CollectedAt, d.Memory.CollectedAt, d.Disk.CollectedAt = at, at, at, at
	raw, err := bundle.Encode(d)
	if err != nil {
		t.Fatal("stale fixture encoding")
	}
	var observation bundle.Bundle
	if json.Unmarshal(raw, &observation) != nil {
		t.Fatal("stale fixture decoding")
	}
	observation.GeneratedAt = at
	raw, err = json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: observation})
	if err != nil {
		t.Fatal("stale frame encoding")
	}
	state := f.openState(t)
	if _, err = state.Stage(1, raw); err != nil {
		t.Fatal("stale fixture staging")
	}
	if state.Close() != nil {
		t.Fatal("stale fixture close")
	}
	_, events := foregroundOneResult(t, f, agentloop.Finished)
	if len(events) != 3 || events[1].Outcome != agentloop.Success || events[1].Metadata.Sequence != 2 || !events[1].Metadata.DiscardedStale || events[1].Metadata.RetriedPending {
		t.Fatal("stale pending sample was not replaced by a higher-sequence fresh collection")
	}
	devices, err := f.store.Devices(context.Background(), f.registry.List(), time.Now())
	if err != nil || len(devices) != 1 || !devices[0].LastSeen.After(at) || devices[0].OS == d.OS {
		t.Fatal("fresh sample did not reach the manager")
	}
	state = f.openState(t)
	if sequence, err := state.NextSequence(); err != nil || sequence != 3 {
		t.Fatal("stale discard reused a consumed sequence")
	}
}

func TestIndependentForegroundCancellationRetainsPendingAndReleasesLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newForegroundBoundaryFixture(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, lanclient.MaxFrameBytes+1))
			cancel()
			w.WriteHeader(http.StatusServiceUnavailable)
		})
	})
	summary, err := lanclient.RunForeground(ctx, f.material, agentloop.MinInterval, nil)
	if !errors.Is(err, context.Canceled) || summary.Reason != agentloop.Cancelled || summary.Attempts != 1 || summary.LastOutcome != "" {
		t.Fatal("in-flight cancellation published a successful outcome")
	}
	state := f.openState(t)
	pending, err := state.Pending()
	if err != nil || pending == nil || pending.Sequence != 1 {
		t.Fatal("cancellation discarded an unacknowledged request")
	}
}

func TestIndependentForegroundUnconfirmedRevocationRemainsRetryable(t *testing.T) {
	f := newForegroundBoundaryFixture(t, nil)
	if err := f.registry.Revoke(context.Background(), f.config.AgentID); err != nil {
		t.Fatal("fixture revocation")
	}
	_, events := foregroundOneResult(t, f, agentloop.Waiting)
	if len(events) != 4 || events[1].Outcome != agentloop.Retryable || events[2].Phase != agentloop.Waiting {
		t.Fatal("unconfirmed transport failure acquired a false acknowledgment or revocation claim")
	}
	state := f.openState(t)
	pending, err := state.Pending()
	if err != nil || pending == nil || pending.Sequence != 1 {
		t.Fatal("denied delivery did not retain pending data")
	}
	devices, err := f.store.Devices(context.Background(), f.registry.List(), time.Now())
	if err != nil || len(devices) != 1 || !devices[0].LastSeen.IsZero() {
		t.Fatal("rejected agent appeared to have reported")
	}
}
