//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowssoftwareipc"
	"localrmm/internal/windowssoftwarejob"
)

type softwareRelayStore map[string][]byte

func (s softwareRelayStore) Read(n string) ([]byte, error) {
	v, ok := s[n]
	if !ok {
		return nil, windowssoftwarejob.ErrIntegrity
	}
	return bytes.Clone(v), nil
}
func (s softwareRelayStore) Write(n string, v []byte) error { s[n] = bytes.Clone(v); return nil }
func (s softwareRelayStore) Verify() error                  { return nil }

type softwareRelayAuthority struct{ current windowssoftwarejob.Current }

func (a *softwareRelayAuthority) WithCurrent(ctx context.Context, _ windowssoftwarejob.Binding, fn func(windowssoftwarejob.Current) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return fn(a.current)
}

type softwareRelayAdapter struct {
	readiness       windowssoftwarejob.Readiness
	opens, installs int
	now             func() time.Time
}

func (a *softwareRelayAdapter) PrepareExact(context.Context, windowssoftwarejob.Selection) (windowssoftwarejob.PreparedPackage, error) {
	a.opens++
	return a, nil
}
func (a *softwareRelayAdapter) Inspect(context.Context) (windowssoftwarejob.Readiness, error) {
	r := a.readiness
	if a.now != nil {
		r.CapturedAt = a.now().Unix()
	}
	return r, nil
}
func (a *softwareRelayAdapter) InstallOnce(context.Context) (windowssoftwarejob.NativeResult, error) {
	a.installs++
	return windowssoftwarejob.NativeResult{ReturnCodeKnown: true, ReturnCode: 0, RegistrationVerified: windowssoftwarejob.Yes}, nil
}
func (a *softwareRelayAdapter) Close() error { return nil }

type softwareRelayBridge struct {
	x                         *windowssoftwarejob.Executor
	readiness, submits, peers int
	lost                      string
	after                     func(string)
	forwarded                 [][]byte
}

func (b *softwareRelayBridge) hook(stage string) {
	if b.after != nil {
		b.after(stage)
	}
}
func (b *softwareRelayBridge) CheckPeer(context.Context, windowssoftwarejob.Binding) error {
	b.peers++
	b.hook("peer")
	return nil
}
func (b *softwareRelayBridge) Readiness(ctx context.Context, v []byte) ([]byte, error) {
	b.readiness++
	b.forwarded = append(b.forwarded, bytes.Clone(v))
	out, e := b.x.Readiness(ctx, v)
	b.hook("readiness")
	if b.lost == "readiness" {
		b.lost = ""
		return nil, errors.New("fixture response lost")
	}
	return out, e
}
func (b *softwareRelayBridge) Submit(ctx context.Context, v []byte) error {
	b.submits++
	b.forwarded = append(b.forwarded, bytes.Clone(v))
	_, e := b.x.Execute(ctx, v)
	b.hook("submit")
	if b.lost == "submit" {
		b.lost = ""
		return errors.New("fixture response lost")
	}
	return e
}
func (b *softwareRelayBridge) Status(ctx context.Context) (windowssoftwarejob.ExecutorStatus, error) {
	v, e := b.x.Status(ctx)
	b.hook("status")
	return v, e
}
func (b *softwareRelayBridge) Outbox(ctx context.Context, k, id, d string) ([]byte, error) {
	v, e := b.x.Outbox(ctx, k, id, d)
	b.hook("outbox")
	return v, e
}

type softwareRelayFixture struct {
	sender          *windowsSoftwareJobSender
	manager         *windowssoftwarejob.Manager
	bridge          *softwareRelayBridge
	adapter         *softwareRelayAdapter
	grant           WindowsSoftwareRelayGrant
	at              time.Time
	id, actor       string
	lost            string
	after           func(string)
	claims, reports [][]byte
	paths           []string
}

func newSoftwareRelayFixture(t *testing.T) *softwareRelayFixture {
	t.Helper()
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	x := &softwareRelayFixture{at: time.Now().UTC().Truncate(time.Second), id: "software_" + strings.Repeat("8", 32), actor: "operator_" + strings.Repeat("9", 32)}
	clock := func() time.Time {
		now := time.Now().UTC()
		if x.at.After(now) {
			return x.at
		}
		return now
	}
	managerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32))
	executorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{212}, 32))
	binding := windowssoftwarejob.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.material.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(f.material), ExecutorID: "executor_" + strings.Repeat("7", 32), ExecutorKeyID: actionpermit.Digest(executorKey.Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: actionpermit.Digest(managerKey.Public().(ed25519.PublicKey))}
	selection := windowssoftwarejob.Selection{SHA256: actionpermit.Digest([]byte("package bytes")), Size: 1024, ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Relay fixture", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "fixture review"}
	consent := windowssoftwarejob.Consent{Package: selection, NativeAcceptanceDigest: actionpermit.Digest([]byte("fixture acceptance")), PackageReviewAccepted: true, Version: windowssoftwarejob.ConsentVersion, Scope: windowssoftwarejob.Scope, Binding: binding, Enabled: true, Acknowledged: true, ExpiresAt: x.at.Unix() + 3600}
	if e := f.store.SetupWindowsSoftwareJobsCreateOnly(context.Background(), managerKey.Public().(ed25519.PublicKey), executorKey.Public().(ed25519.PublicKey), consent, x.at); e != nil {
		t.Fatal(e)
	}
	var e error
	x.manager, e = windowssoftwarejob.OpenTransactional(context.Background(), f.store, binding, managerKey, clock)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.manager.ConfigureOperatorPolicy(func(actor string) bool { return actor == x.actor }); e != nil {
		t.Fatal(e)
	}
	if e = f.ingress.ConfigureWindowsSoftwareJobs(x.manager); e != nil {
		t.Fatal(e)
	}
	x.grant = WindowsSoftwareRelayGrant{Version: WindowsSoftwareRelayGrantVersion, Scope: WindowsSoftwareRelayScope, Enabled: true, Acknowledged: true, SenderBinding: f.material.binding, ManagerOrigin: f.material.config.ManagerOrigin, Binding: binding, ManagerPublicKey: managerKey.Public().(ed25519.PublicKey), ExecutorPublicKey: executorKey.Public().(ed25519.PublicKey), ExpiresAt: consent.ExpiresAt}
	x.grant.ExecutorPeer = windowssoftwareipc.PeerConfig{Version: windowssoftwareipc.PeerVersion, Binding: binding, ExecutorPublicKey: executorKey.Public().(ed25519.PublicKey), Executable: `C:\Program Files\Tracebolt\tracebolt-windows-software-executor.exe`, ExecutableDigest: actionpermit.Digest([]byte("fixture executable")), ConfigurationDigest: actionpermit.Digest([]byte("fixture public executor config"))}
	x.adapter = &softwareRelayAdapter{now: clock, readiness: windowssoftwarejob.Readiness{Selection: selection, CapturedAt: x.at.Unix(), PackageVerified: windowssoftwarejob.Yes, MachineAbsent: windowssoftwarejob.Yes, InstallerBusy: windowssoftwarejob.No, NativeAcceptance: windowssoftwarejob.Yes, PackageReviewAccepted: windowssoftwarejob.Yes, MaintenanceWindowEnd: x.at.Unix() + 600}}
	record, e := windowssoftwarejob.NewExecutorRecord(consent, managerKey.Public().(ed25519.PublicKey), executorKey.Public().(ed25519.PublicKey), x.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := windowssoftwarejob.EncodeExecutorRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	c, _ := json.Marshal(consent)
	store := softwareRelayStore{"executor.json": raw, "started.json": c, "receipt.json": c}
	guard := &softwareRelayAuthority{current: windowssoftwarejob.Current{Binding: binding, LeafDigest: actionpermit.Digest(f.material.certificate.Certificate[0]), LeafGeneration: 1, LeafNotBefore: x.at.Unix() - 60, LeafNotAfter: x.at.Unix() + 3600, Enabled: true}}
	executor, e := windowssoftwarejob.OpenExecutor(store, guard, x.adapter, executorKey, clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(executor.Close)
	x.bridge = &softwareRelayBridge{x: executor}
	x.sender = openWindowsSoftwareJobSender(f.material)
	t.Cleanup(x.sender.Close)
	x.sender.current = func(Material) bool { return true }
	x.sender.local = func(Material) (WindowsSoftwareRelayGrant, error) { return x.grant, nil }
	x.sender.now = clock
	x.sender.executor = x.bridge
	x.sender.newExecutor = nil
	x.sender.client = &http.Client{Transport: fullServicesRoundTrip(func(r *http.Request) (*http.Response, error) {
		leaf, _ := x509.ParseCertificate(f.material.certificate.Certificate[0])
		issuer, _ := x509.ParseCertificate(f.issuer.IssuerDER())
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}
		requestBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(requestBytes))
		w := httptest.NewRecorder()
		f.ingress.ServeHTTP(w, r)
		path := strings.TrimPrefix(r.URL.Path, windowsSoftwareJobsRelayPrefix)
		x.paths = append(x.paths, path)
		if w.Code == http.StatusOK && (path == "readiness-claim" || path == "install-claim") {
			x.claims = append(x.claims, bytes.Clone(w.Body.Bytes()))
		}
		if path == "report" {
			x.reports = append(x.reports, bytes.Clone(requestBytes))
		}
		if x.after != nil {
			x.after(path)
		}
		if x.lost == path {
			x.lost = ""
			return nil, errors.New("fixture response lost")
		}
		return w.Result(), nil
	})}
	return x
}
func (x *softwareRelayFixture) request(t *testing.T) {
	t.Helper()
	if e := x.manager.Request(context.Background(), x.grant.Binding.DeviceID, x.actor, x.id, x.adapter.readiness.Selection); e != nil {
		t.Fatal(e)
	}
}
func (x *softwareRelayFixture) approve(t *testing.T) {
	t.Helper()
	v, e := x.manager.View(context.Background(), x.grant.Binding.DeviceID, x.actor)
	if e != nil || v.Job == nil || v.Job.Preview == nil {
		t.Fatal("preview", v, e)
	}
	if e = x.manager.Approve(context.Background(), x.grant.Binding.DeviceID, x.actor, x.id, v.Job.Preview.Digest, true); e != nil {
		t.Fatal(e)
	}
}
func (x *softwareRelayFixture) run(t *testing.T, want string) {
	t.Helper()
	if got := x.sender.Run(context.Background()); got != want {
		t.Fatalf("got %s want %s (paths %v)", got, want, x.paths)
	}
}

func TestWindowsSoftwareRelayExactSignedRoundTrip(t *testing.T) {
	x := newSoftwareRelayFixture(t)
	x.request(t)
	x.run(t, "reported")
	x.approve(t)
	x.run(t, "reported")
	x.run(t, "idle")
	if x.bridge.readiness != 1 || x.bridge.submits != 1 || x.adapter.installs != 1 || len(x.claims) != 2 || len(x.bridge.forwarded) != 2 {
		t.Fatal("wrong source calls")
	}
	for i := range x.claims {
		if !bytes.Equal(x.claims[i], x.bridge.forwarded[i]) {
			t.Fatal("signed request changed")
		}
	}
	for _, report := range x.reports {
		statement, e := windowssoftwarejob.VerifyStatement(report, x.grant.ExecutorPublicKey)
		if e != nil {
			t.Fatal("report signature changed", e)
		}
		saved, e := x.bridge.x.Outbox(context.Background(), statement.Kind, statement.JobID, statement.ReferenceDigest)
		if e != nil || !bytes.Equal(report, saved) {
			t.Fatal("report not original saved bytes", e)
		}
	}
	view, e := x.manager.View(context.Background(), x.grant.Binding.DeviceID, x.actor)
	if e != nil || view.Job.Result == nil || view.Job.Result.Outcome != "succeeded" {
		t.Fatal(view, e)
	}
}
func TestWindowsSoftwareRelayLostResponsesNeverRedispatch(t *testing.T) {
	for _, stage := range []string{"readiness-claim", "readiness", "install-claim", "submit", "report"} {
		t.Run(stage, func(t *testing.T) {
			x := newSoftwareRelayFixture(t)
			x.request(t)
			install := stage == "install-claim" || stage == "submit" || stage == "report"
			if install {
				x.run(t, "reported")
				x.approve(t)
			}
			if stage == "readiness" || stage == "submit" {
				x.bridge.lost = stage
			} else {
				x.lost = stage
			}
			x.run(t, "outcome_unknown")
			// A new observer process forgets only its report-ack optimization. The
			// manager claim and executor durable state remain the sole no-retry fences.
			x.sender.delivered = map[string]string{}
			x.run(t, "idle")
			x.run(t, "idle")
			wantReadiness := 1
			if stage == "readiness-claim" {
				wantReadiness = 0
			}
			wantInstall := 0
			if stage == "submit" || stage == "report" {
				wantInstall = 1
			}
			if x.bridge.readiness != wantReadiness || x.bridge.submits != wantInstall || x.adapter.installs != wantInstall {
				t.Fatal("lost reply repeated source/installation", x.bridge.readiness, x.bridge.submits, x.adapter.installs)
			}
		})
	}
}
func TestWindowsSoftwareRelayDefaultOffAndGrantAuthority(t *testing.T) {
	x := newSoftwareRelayFixture(t)
	original := x.grant
	x.sender.executor = unavailableWindowsSoftwareExecutorClient{}
	x.run(t, "unavailable")
	if len(x.paths) != 0 {
		t.Fatal("unverified peer reached manager")
	}
	x.sender.executor = x.bridge
	for _, which := range []string{"disabled", "ack", "expiry", "origin", "binding", "scope", "pin", "shared_key", "http", "current", "old_grant", "peer_binding", "peer_image", "peer_config"} {
		t.Run(which, func(t *testing.T) {
			x.grant = original
			x.sender.material.config.Profile = "tls"
			x.sender.current = func(Material) bool { return true }
			want := "denied"
			switch which {
			case "disabled":
				x.grant.Enabled = false
				want = "disabled"
			case "ack":
				x.grant.Acknowledged = false
			case "expiry":
				x.grant.ExpiresAt = x.at.Unix()
			case "origin":
				x.grant.ManagerOrigin += "/other"
			case "binding":
				x.grant.Binding.IncarnationDigest = actionpermit.Digest([]byte("other"))
			case "scope":
				x.grant.Scope = windowssoftwarejob.Scope
			case "pin":
				x.grant.Binding.KeyID = actionpermit.Digest([]byte("wrong"))
			case "shared_key":
				x.grant.ExecutorPublicKey = x.grant.ManagerPublicKey
				x.grant.Binding.ExecutorKeyID = x.grant.Binding.KeyID
			case "http":
				x.sender.material.config.Profile = "http-test"
			case "old_grant":
				x.grant.Version = "tracebolt.windows-selected-update-observer-relay.v1"
			case "peer_binding":
				x.grant.ExecutorPeer.Binding.GrantID = "grant_" + strings.Repeat("b", 32)
			case "peer_image":
				x.grant.ExecutorPeer.ExecutableDigest = ""
			case "peer_config":
				x.grant.ExecutorPeer.ConfigurationDigest = ""
			case "current":
				x.sender.current = func(Material) bool { return false }
			}
			x.run(t, want)
			if len(x.paths) != 0 {
				t.Fatal("denied grant reached manager")
			}
		})
	}
	x.sender.material.config.Profile = "http-test"
	if openWindowsSoftwareJobSender(x.sender.material) != nil {
		t.Fatal("HTTP prepared MSI relay enabled")
	}
}
func TestWindowsSoftwareRelayRechecksAfterBlockingSteps(t *testing.T) {
	for _, stage := range []string{"status", "poll", "readiness-claim", "readiness", "outbox", "report"} {
		t.Run(stage, func(t *testing.T) {
			x := newSoftwareRelayFixture(t)
			x.request(t)
			disable := func(got string) {
				if got == stage {
					x.grant.Enabled = false
				}
			}
			x.after = disable
			x.bridge.after = disable
			want := "denied"
			if stage == "report" {
				want = "outcome_unknown"
			}
			x.run(t, want)
			if (stage == "status" || stage == "poll" || stage == "readiness-claim") && x.bridge.readiness != 0 {
				t.Fatal("grant changed before dispatch")
			}
			if stage == "readiness" || stage == "outbox" {
				for _, p := range x.paths {
					if p == "report" {
						t.Fatal("grant changed before report")
					}
				}
			}
			if x.adapter.installs != 0 {
				t.Fatal("readiness installed")
			}
		})
	}
}
func TestWindowsSoftwareRelayExpiredOutboxIsNotRenewed(t *testing.T) {
	x := newSoftwareRelayFixture(t)
	x.request(t)
	x.run(t, "reported")
	x.approve(t)
	x.bridge.lost = "submit"
	x.run(t, "outcome_unknown")
	status, err := x.bridge.x.Status(context.Background())
	if err != nil || len(status.Attempts) != 1 {
		t.Fatal("missing saved result expiry", err)
	}
	// Advance past the actual immutable signed completion expiry. Race builds
	// can take seconds between fixture creation and that original completion.
	x.at = time.Unix(status.Attempts[0].ReportExpiresAt+1, 0)
	x.sender.delivered = map[string]string{}
	before := len(x.paths)
	x.sender.exchange = func(context.Context, string, []byte) ([]byte, int, error) { return []byte("null"), http.StatusOK, nil }
	x.run(t, "idle")
	for _, p := range x.paths[before:] {
		if p == "report" {
			t.Fatal("expired report retried")
		}
	}
	if x.bridge.submits != 1 || x.adapter.installs != 1 {
		t.Fatal("expired evidence caused reinstall")
	}
}
func TestWindowsSoftwareRelayRenewalKeepsOriginalGrantAndRejectsStaleLeaf(t *testing.T) {
	f := newRenewalMaterialFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, false)
	before, after := f.material(t, f.initial), f.material(t, f.renewed)
	x := newSoftwareRelayFixture(t)
	g := x.grant
	g.SenderBinding = before.binding
	g.ManagerOrigin = before.config.ManagerOrigin
	g.Binding.DeviceID = before.config.AgentID
	g.Binding.IncarnationDigest = "sha256:" + journalLeaf(before)
	g.ExecutorPeer.Binding = g.Binding
	now := time.Now().UTC()
	if validateWindowsSoftwareRelayGrant(before, g, now) != nil || validateWindowsSoftwareRelayGrant(after, g, now) != nil {
		t.Fatal("renewal changed immutable grant")
	}
	if currentWindowsSoftwareRelayMaterial(before, func(string) (Material, error) { return after, nil }) {
		t.Fatal("stale leaf retained transport authority")
	}
	g.ExpiresAt = now.Unix()
	if validateWindowsSoftwareRelayGrant(after, g, now) == nil {
		t.Fatal("renewal extended grant expiry")
	}
}

func TestWindowsSoftwareRelayFinalBlockingReadCannotExtendExpiry(t *testing.T) {
	t.Run("grant", func(t *testing.T) {
		x := newSoftwareRelayFixture(t)
		g := x.grant
		g.ExpiresAt = x.at.Unix() + 5
		x.grant = g
		calls := 0
		x.sender.current = func(Material) bool {
			calls++
			if calls == 2 {
				x.at = time.Unix(g.ExpiresAt, 0)
			}
			return true
		}
		if x.sender.recheck(context.Background(), g) {
			t.Fatal("final material read extended grant")
		}
	})
	t.Run("signed_report", func(t *testing.T) {
		x := newSoftwareRelayFixture(t)
		x.request(t)
		x.run(t, "reported")
		proof := x.reports[0]
		statement, e := windowssoftwarejob.VerifyStatement(proof, x.grant.ExecutorPublicKey)
		if e != nil {
			t.Fatal(e)
		}
		calls, sends := 0, 0
		x.sender.current = func(Material) bool {
			calls++
			if calls == 2 {
				x.at = time.Unix(statement.ExpiresAt, 0)
			}
			return true
		}
		x.sender.exchange = func(context.Context, string, []byte) ([]byte, int, error) {
			sends++
			return []byte("{}"), http.StatusOK, nil
		}
		if x.sender.report(context.Background(), x.grant, statement.Kind, statement.JobID, statement.ReferenceDigest, statement.Deadline, proof) || sends != 0 {
			t.Fatal("final authority read extended signed report")
		}
	})
}
func TestWindowsSoftwareRelayTamperedClaimsNeverReachExecutor(t *testing.T) {
	for _, kind := range []string{"readiness", "install"} {
		t.Run(kind, func(t *testing.T) {
			x := newSoftwareRelayFixture(t)
			x.request(t)
			if kind == "install" {
				x.run(t, "reported")
				x.approve(t)
			}
			exchange := x.sender.exchange
			x.sender.exchange = func(ctx context.Context, path string, body []byte) ([]byte, int, error) {
				raw, code, e := exchange(ctx, path, body)
				if path == windowsSoftwareJobsRelayPrefix+kind+"-claim" && e == nil && code == http.StatusOK {
					raw = bytes.Clone(raw)
					if raw[len(raw)-3] == 'A' {
						raw[len(raw)-3] = 'B'
					} else {
						raw[len(raw)-3] = 'A'
					}
				}
				return raw, code, e
			}
			x.run(t, "denied")
			x.run(t, "idle")
			want := 0
			if kind == "install" {
				want = 1
			}
			if x.bridge.readiness != want || x.bridge.submits != 0 || x.adapter.installs != 0 {
				t.Fatal("tampered claim reached source")
			}
		})
	}
}
func TestWindowsSoftwareRelayRequestHasNoBlockingPreSendReload(t *testing.T) {
	x := newSoftwareRelayFixture(t)
	calls := 0
	x.sender.current = func(Material) bool { calls++; return true }
	x.sender.client = &http.Client{Transport: fullServicesRoundTrip(func(r *http.Request) (*http.Response, error) {
		if calls != 0 {
			t.Fatal("blocking material reload inserted after caller guard")
		}
		if r.GetBody != nil || r.URL.Scheme != "https" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("invalid TLS-only no-replay request")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, ContentLength: 4, Body: io.NopCloser(strings.NewReader("null"))}, nil
	})}
	if _, _, e := x.sender.request(context.Background(), windowsSoftwareJobsRelayPrefix+"poll", []byte("{}")); e != nil || calls != 1 {
		t.Fatal("missing post-response current check", e, calls)
	}
}

func TestWindowsSoftwareRelayFreshPeerFactoryIsDefaultOff(t *testing.T) {
	x := newSoftwareRelayFixture(t)
	production := openWindowsSoftwareJobSender(x.sender.material)
	defer production.Close()
	if production.newExecutor == nil {
		t.Fatal("missing protected client factory")
	}
	x.sender.newExecutor = production.newExecutor
	// Non-Windows source fixtures have no verified native peer. Public pins alone
	// must never permit network polling or manufacture local peer trust.
	x.run(t, "unavailable")
	if len(x.paths) != 0 {
		t.Fatal("unproven peer reached manager")
	}
	calls := 0
	x.sender.newExecutor = func(g WindowsSoftwareRelayGrant) (windowsSoftwareExecutorClient, error) {
		calls++
		x.grant.Enabled = false
		return x.bridge, nil
	}
	x.run(t, "unavailable")
	if calls != 1 || len(x.paths) != 0 {
		t.Fatal("factory widened current grant")
	}
	x.run(t, "disabled")
	if calls != 1 {
		t.Fatal("disabled grant constructed a client")
	}
}
