//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/managerreadiness"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func readinessComponent(t *testing.T, v managerreadiness.View, name string) managerreadiness.Component {
	t.Helper()
	for _, c := range v.Components {
		if c.Component == name {
			return c
		}
	}
	t.Fatal("missing fixed component", name)
	return managerreadiness.Component{}
}

func readinessLifetime(t *testing.T, v managerreadiness.View, role string) managerreadiness.CertificateLifetime {
	t.Helper()
	for _, lifetime := range v.CertificateLifetimes {
		if lifetime.Role == role {
			return lifetime
		}
	}
	t.Fatal("missing fixed certificate role", role)
	return managerreadiness.CertificateLifetime{}
}

func TestManagerReadinessRealPreparedStoresAndPublicIssuer(t *testing.T) {
	m, enrollment, _ := guidedFixture(t, lanconfig.TLS)
	p, err := prepareWithEnrollment(m, &enrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	retained := map[string][]byte{}
	entries, err := os.ReadDir(m.Config.StateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "-shm") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.Config.StateDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		retained[entry.Name()] = raw
	}
	v := p.readiness.Snapshot(context.Background())
	if v.Status != "ready" || readinessComponent(t, v, "linux_enrollment_store").State != "ready" || readinessComponent(t, v, "enrollment_issuer").State != "ready" || readinessComponent(t, v, "windows_enrollment_store").State != "not_configured" || readinessComponent(t, v, "linux_inventory_step").State != "not_configured" {
		t.Fatal("real configured core view", v)
	}
	for name, before := range retained {
		after, err := os.ReadFile(filepath.Join(m.Config.StateDirectory, name))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("read changed private state", name)
		}
	}
	raw, _ := json.Marshal(v)
	for _, private := range []string{m.Config.StateDirectory, enrollment.StoreConfig().Binding.InstanceID, enrollment.Issuer().Fingerprint(), m.PasswordHash} {
		if private != "" && bytes.Contains(raw, []byte(private)) {
			t.Fatal("private identifying material exposed")
		}
	}
	cert, _ := x509.ParseCertificate(enrollment.Issuer().IssuerDER())
	root, _ := x509.ParseCertificate(enrollment.Issuer().RootDER())
	if got := readinessLifetime(t, v, "enrollment_issuer"); got.ValidUntil == nil || !got.ValidUntil.Equal(cert.NotAfter) {
		t.Fatal("loaded issuer deadline missing", got)
	}
	if got := readinessLifetime(t, v, "enrollment_root"); got.ValidUntil == nil || !got.ValidUntil.Equal(root.NotAfter) {
		t.Fatal("loaded root deadline missing", got)
	}
	p.readiness.now = func() time.Time { return cert.NotAfter }
	v = p.readiness.Snapshot(context.Background())
	if readinessComponent(t, v, "enrollment_issuer").State != "failed" || v.Status == "ready" || readinessLifetime(t, v, "enrollment_issuer").State != "expired" {
		t.Fatal("issuer exact expiry accepted")
	}
}

func TestManagerReadinessManualModeAndProtectedFileReplacement(t *testing.T) {
	m, _, _, _ := fixture(t, lanconfig.HTTPTest)
	p, err := prepare(m)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	v := p.readiness.Snapshot(context.Background())
	if v.Status != "ready" || readinessComponent(t, v, "enrollment_issuer").State != "not_configured" || readinessComponent(t, v, "server_certificate").State != "not_configured" {
		t.Fatal("manual HTTP-test view", v)
	}
	if len(v.CertificateLifetimes) != 3 {
		t.Fatal("missing fixed certificate roster")
	}
	for _, lifetime := range v.CertificateLifetimes {
		if lifetime.State != "not_configured" || lifetime.ValidFrom != nil || lifetime.ValidUntil != nil {
			t.Fatal("HTTP-test claimed TLS or issuer material", lifetime)
		}
	}
	path := filepath.Join(m.Config.StateDirectory, "operator.db")
	if err := os.Rename(path, path+".preserved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement fixture, never repaired"), 0600); err != nil {
		t.Fatal(err)
	}
	v = p.readiness.Snapshot(context.Background())
	if v.Status == "ready" || readinessComponent(t, v, "operator_store").State != "failed" {
		t.Fatal("old live handle concealed replaced path", v)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "replacement fixture, never repaired" {
		t.Fatal("probe repaired replacement")
	}
	if err := os.WriteFile(filepath.Join(m.Config.StateDirectory, lanstore.RestoreQuarantineFile), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if readinessComponent(t, p.readiness.Snapshot(context.Background()), "state_boundary").State != "failed" {
		t.Fatal("quarantine appeared ready")
	}
}

func TestManagerReadinessSingleAdmissionAndCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r := &managerReadiness{admission: make(chan struct{}, 1), now: time.Now, checks: []managerReadinessCheck{{"store", func(context.Context) error { calls.Add(1); close(started); <-release; return nil }}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan managerreadiness.View, 1)
	go func() { done <- r.Snapshot(ctx) }()
	<-started
	cancel()
	busy := r.Snapshot(context.Background())
	if busy.Status == "ready" || readinessComponent(t, busy, "probe").State != "busy" || calls.Load() != 1 {
		t.Fatal("second probe bypassed occupied slot")
	}
	close(release)
	v := <-done
	if v.Status == "ready" || readinessComponent(t, v, "store").State != "timeout" {
		t.Fatal("late canceled result accepted")
	}
	canceled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if r.Snapshot(canceled).Status == "ready" || calls.Load() != 1 {
		t.Fatal("already canceled context entered store")
	}
}

func TestManagerReadinessSlowProbeRetainsRequestDrainOwnership(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	r := &managerReadiness{admission: make(chan struct{}, 1), now: time.Now, checks: []managerReadinessCheck{{"store", func(context.Context) error { close(started); <-release; return nil }}}}
	drain := newManagerRequestDrain()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/manager/readiness", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		drain.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { _ = r.Snapshot(ctx) })).ServeHTTP(httptest.NewRecorder(), request)
	}()
	<-started
	cancel()
	drain.Stop()
	cleaned := make(chan struct{})
	drain.CloseAfterDrain(func() { close(cleaned) })
	select {
	case <-cleaned:
		t.Fatal("store closed while slow probe still used it")
	default:
	}
	if drain.Drained() {
		t.Fatal("probe ownership released at context cancellation")
	}
	close(release)
	<-done
	select {
	case <-cleaned:
	case <-time.After(time.Second):
		t.Fatal("finished probe retained state")
	}
}

func TestManagerReadinessWorkerEvidenceIsRequired(t *testing.T) {
	at := time.Now().UTC()
	r := &managerReadiness{admission: make(chan struct{}, 1), now: func() time.Time { return at }, checks: []managerReadinessCheck{{"store", func(context.Context) error { return nil }}}, linuxInventory: managerreadiness.NewWorker(time.Second)}
	if r.Snapshot(context.Background()).Status == "ready" {
		t.Fatal("configured unstarted worker ready")
	}
	r.linuxInventory.Start()
	if r.Snapshot(context.Background()).Status == "ready" {
		t.Fatal("running alone ready")
	}
	r.linuxInventory.Complete(at, nil)
	v := r.Snapshot(context.Background())
	if v.Status != "ready" || v.Scope != "core_reads_and_last_worker_steps" || readinessComponent(t, v, "linux_inventory_step").State != "succeeded" {
		t.Fatal("fresh step evidence contract", v)
	}
	found := false
	for _, excluded := range v.Unassessed {
		if excluded == "complete_maintenance_sweep" {
			found = true
		}
	}
	if !found {
		t.Fatal("whole sweep exclusion omitted")
	}
	at = at.Add(2 * time.Second)
	if r.Snapshot(context.Background()).Status == "ready" {
		t.Fatal("GET refreshed old worker success")
	}
}

func TestManagerReadinessPresentedChainExpiry(t *testing.T) {
	_, certPEM, _, _, _, _ := fixtureTLS(t)
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := &managerReadiness{admission: make(chan struct{}, 1), now: func() time.Time { return now }, tls: true, certificate: [][]byte{leaf.Raw}, checks: []managerReadinessCheck{{"store", func(context.Context) error { return nil }}}}
	if readinessComponent(t, r.Snapshot(context.Background()), "server_certificate").State != "ready" {
		t.Fatal("valid loaded leaf rejected")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expired := &x509.Certificate{SerialNumber: big.NewInt(700), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * time.Second), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, expired, expired, public, private)
	if err != nil {
		t.Fatal(err)
	}
	material := lanconfig.Material{Config: lanconfig.Config{Profile: lanconfig.TLS}, Server: tls.Certificate{Certificate: [][]byte{leaf.Raw, der}}}
	r = newManagerReadiness(material, nil, nil, nil, nil, nil, nil, nil)
	r.now = func() time.Time { return now }
	r.checks = []managerReadinessCheck{{"store", func(context.Context) error { return nil }}}
	if len(r.certificate) != 2 {
		t.Fatal("constructor omitted loaded chain")
	}
	material.Server.Certificate[1][0] ^= 1
	if bytes.Equal(r.certificate[1], material.Server.Certificate[1]) {
		t.Fatal("constructor retained mutable certificate bytes")
	}
	if readinessComponent(t, r.Snapshot(context.Background()), "server_certificate").State != "ready" {
		t.Fatal("valid loaded chain rejected")
	}
	if got := readinessLifetime(t, r.Snapshot(context.Background()), "server_chain"); got.State != "within_7_days" || got.ValidUntil == nil || !got.ValidUntil.Equal(expired.NotAfter) {
		t.Fatal("presented intermediate deadline hidden", got)
	}
	now = expired.NotAfter
	v := r.Snapshot(context.Background())
	if readinessComponent(t, v, "server_certificate").State != "failed" || readinessLifetime(t, v, "server_chain").State != "expired" {
		t.Fatal("live leaf concealed expired presented intermediate")
	}
	r.certificate = r.certificate[:1]
	for _, invalidAt := range []time.Time{leaf.NotBefore.Add(-time.Nanosecond), leaf.NotAfter} {
		now = invalidAt
		if readinessComponent(t, r.Snapshot(context.Background()), "server_certificate").State != "failed" {
			t.Fatal("certificate validity boundary accepted")
		}
	}
}

func TestManagerReadinessLifetimeNeverReloadsFilesOrChangesValidation(t *testing.T) {
	m, enrollment, _ := guidedFixture(t, lanconfig.TLS)
	p, err := prepareWithEnrollment(m, &enrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	before := p.readiness.Snapshot(context.Background())
	expires := readinessLifetime(t, before, "server_chain").ValidUntil
	// Readiness owns a defensive public copy. Changing caller material cannot
	// refresh the loaded lifetime or make Snapshot read credential paths again.
	for _, der := range m.Server.Certificate {
		clear(der)
	}
	p.readiness.now = func() time.Time { return before.ServerNow.Add(time.Second) }
	after := p.readiness.Snapshot(context.Background())
	if got := readinessLifetime(t, after, "server_chain"); expires == nil || got.ValidUntil == nil || !got.ValidUntil.Equal(*expires) {
		t.Fatal("snapshot replaced original loaded certificate deadline", got)
	}
	// Parsable dates alone cannot override the existing fingerprint/role/trust
	// validator. This remains an unavailable readiness result.
	p.readiness.fingerprint = strings.Repeat("0", 64)
	after = p.readiness.Snapshot(context.Background())
	if after.Status != "unavailable" || readinessComponent(t, after, "enrollment_issuer").State != "failed" || readinessLifetime(t, after, "enrollment_issuer").ValidUntil == nil {
		t.Fatal("lifetime report promoted invalid authority", after)
	}
}
