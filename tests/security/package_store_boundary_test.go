//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/analysis"
	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/operational"
	"localrmm/internal/signedhttp"
)

// All keys are ordinary ephemeral generated fixtures. All observations are
// synthetic. No production collector, package database, APT or advisory source
// participates. A new profile always receives a fresh, separate store path.
func packageStoreFresh(t *testing.T, f *independentServiceFixture) *independentServiceFixture {
	t.Helper()
	cfg := f.store.Config()
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	f.path = filepath.Join(t.TempDir(), "private", "packages.sqlite")
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	var err error
	f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func packageStoreFixture(t *testing.T) (*independentServiceFixture, enrollmentstate.Snapshot) {
	t.Helper()
	f := packageStoreFresh(t, independentServiceNew(t, false))
	return f, operationalStoreActivate(t, f)
}
func packageStoreSnapshot(op operational.Snapshot, healthy bool) linuxpackages.Snapshot {
	s := linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: op.GenerationID, CollectedAt: op.CollectedAt,
		Release:   linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing},
		Inventory: linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing, Items: []linuxpackages.PackageRow{}}}
	if healthy {
		id, version, codename, n := "debian", "13", "trixie", uint64(1)
		s.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}}
		s.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true, ObservedCount: &n, InstalledCount: &n,
			Items: []linuxpackages.PackageRow{{Name: "fixture-binary", Version: "1.0-1+b1", Architecture: "amd64", SourcePackage: "fixture-source", SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}}}
	}
	return s
}
func packageStoreFrame(t *testing.T, seq uint64, op operational.Snapshot, packages linuxpackages.Snapshot, padded bool) []byte {
	t.Helper()
	var frame lanstore.Frame
	if err := json.Unmarshal(operationalStoreFrame(t, seq, op.CollectedAt, &op), &frame); err != nil {
		t.Fatal(err)
	}
	frame.SchemaVersion, frame.Packages = lanstore.FramePackagesVersion, &packages
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > lanstore.MaxFrameBytes {
		t.Fatal("invalid fixture frame size", err)
	}
	if padded {
		raw = append(raw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
	}
	if _, err := lanstore.ValidateFrame(raw, op.CollectedAt); err != nil {
		t.Fatal("invalid package fixture", err)
	}
	return raw
}
func packageStoreSize(t *testing.T, value any) int {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

func TestIndependentPackageStoreLatestOnlyCloneExpiryAndExactRestart(t *testing.T) {
	f, identity := packageStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(at, "services")
	pkg := packageStoreSnapshot(op, true)
	raw := packageStoreFrame(t, 1, op, pkg, false)
	receipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	if err != nil {
		t.Fatal(err)
	}
	before := operationalStoreRows(t, f.path)
	view, err := f.store.PackageView(ctx, identity.Approval.DeviceID, at)
	if err != nil || view.Status != "fresh" || view.Snapshot == nil {
		t.Fatal("missing fresh package view", err)
	}
	*view.Snapshot.Release.Fields.ID = "mutated"
	*view.Snapshot.Release.Fields.VersionID = "mutated"
	*view.Snapshot.Release.Fields.VersionCodename = "mutated"
	*view.Snapshot.Inventory.ObservedCount = 99
	*view.Snapshot.Inventory.InstalledCount = 99
	view.Snapshot.Inventory.Items[0].Name = "mutated"
	*view.Sequence = 99
	*view.ReceivedAt = at.Add(time.Hour)
	again, err := f.store.PackageView(ctx, identity.Approval.DeviceID, at)
	if err != nil || !bytes.Equal(before, operationalStoreRows(t, f.path)) || packageStoreSize(t, again.Snapshot) != packageStoreSize(t, pkg) {
		t.Fatal("package read aliased durable state", err)
	}
	encoded, _ := json.Marshal(again.Snapshot)
	expected, _ := json.Marshal(pkg)
	if !bytes.Equal(encoded, expected) || *again.Sequence != receipt.Sequence || !again.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("mutable package result escaped isolation")
	}
	for _, tc := range []struct {
		when    time.Time
		status  string
		visible bool
	}{
		{at.Add(lanstore.SampleMaxAge), "fresh", true}, {at.Add(lanstore.SampleMaxAge + time.Nanosecond), "stale", true}, {at.Add(-time.Nanosecond), "stale", true},
		{at.Add(enrollmentstore.OperationalRetention - time.Nanosecond), "stale", true}, {at.Add(enrollmentstore.OperationalRetention), "unavailable", false},
	} {
		got, err := f.store.PackageView(ctx, identity.Approval.DeviceID, tc.when)
		if err != nil || got.Status != tc.status || (got.Snapshot != nil) != tc.visible || got.Sequence == nil || *got.Sequence != 1 || !got.ReceivedAt.Equal(at) {
			t.Fatal("package visibility/age boundary failed", tc.status, err)
		}
		if got.Snapshot != nil && got.Snapshot.Inventory.Quality != linuxpackages.Healthy {
			t.Fatal("server age rewrote original source quality")
		}
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("package expiry deleted or modified retained exact frame")
	}
	cfg := f.store.Config()
	f.store.Close()
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	duplicate, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at.Add(enrollmentstore.OperationalRetention))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) || !duplicate.CollectedAt.Equal(receipt.CollectedAt) {
		t.Fatal("historical package retry lost original receipt", err)
	}
	// Source failure is a new observation, never a merge with the previous package facts.
	nextAt := at.Add(enrollmentstore.OperationalRetention + time.Second)
	nextOp := operationalStoreSnapshot(nextAt, "")
	unknown := packageStoreSnapshot(nextOp, false)
	next := packageStoreFrame(t, 2, nextOp, unknown, false)
	if _, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.PackageView(ctx, identity.Approval.DeviceID, nextAt)
	if err != nil || current.Status != "fresh" || current.Snapshot == nil || current.Snapshot.Inventory.Quality != linuxpackages.Unknown || current.Snapshot.Inventory.ObservedCount != nil || current.Snapshot.Release.Fields.ID != nil || len(current.Snapshot.Inventory.Items) != 0 {
		t.Fatal("unknown latest source retained old package facts", err)
	}
	before = operationalStoreRows(t, f.path)
	duplicate, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt.Add(time.Minute))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(nextAt) || !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("fresh exact duplicate changed frame/cache/receipt", err)
	}
}

func TestIndependentPackageStoreRejectedAdmissionsAndCurrentAuthority(t *testing.T) {
	f, identity := packageStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(at, "services")
	raw := packageStoreFrame(t, 1, op, packageStoreSnapshot(op, true), false)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal(err)
	}
	nextAt := at.Add(time.Second)
	nextOp := operationalStoreSnapshot(nextAt, "software")
	nextPkg := packageStoreSnapshot(nextOp, true)
	next := packageStoreFrame(t, 2, nextOp, nextPkg, false)
	sameGeneration := operationalStoreUniqueGeneration(nextOp, 1)
	sameGeneration.GenerationID = op.GenerationID
	for _, m := range []*operational.SectionMeta{&sameGeneration.Sections.Volumes.Meta, &sameGeneration.Sections.Network.Meta, &sameGeneration.Sections.Services.Meta, &sameGeneration.Sections.Processes.Meta, &sameGeneration.Sections.Software.Meta, &sameGeneration.Sections.Events.Meta} {
		m.GenerationID = op.GenerationID
	}
	cases := []struct {
		name string
		raw  []byte
		hash string
		when time.Time
		want error
	}{
		{"wrong certificate", next, strings.Repeat("a", 64), nextAt, enrollmentstate.ErrProof},
		{"legacy operational frame", operationalStoreFrame(t, 2, nextAt, &nextOp), identity.Issuance.CertificateHash, nextAt, enrollmentstate.ErrProof},
		{"basic frame", operationalStoreFrame(t, 2, nextAt, nil), identity.Issuance.CertificateHash, nextAt, enrollmentstate.ErrProof},
		{"old sequence", packageStoreFrame(t, 1, nextOp, nextPkg, false), identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"old capture", packageStoreFrame(t, 2, op, packageStoreSnapshot(op, true), false), identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"same generation", packageStoreFrame(t, 2, sameGeneration, packageStoreSnapshot(sameGeneration, true), false), identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"stale capture", next, identity.Issuance.CertificateHash, nextAt.Add(3 * time.Minute), lanstore.ErrStale},
		{"backward receipt", next, identity.Issuance.CertificateHash, at.Add(-time.Nanosecond), enrollmentstate.ErrInvalid},
		{"duplicate package key", bytes.Replace(next, []byte(`"sourceMapping":"source-field"`), []byte(`"sourceMapping":"source-field","sourceMapping":"source-field"`), 1), identity.Issuance.CertificateHash, nextAt, lanstore.ErrFrame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := operationalStoreRows(t, f.path)
			got, err := f.store.SaveObservation(ctx, identity.InvitationID, tc.hash, tc.raw, tc.when)
			if !errors.Is(err, tc.want) || got != (lanstore.Receipt{}) || !bytes.Equal(before, operationalStoreRows(t, f.path)) {
				t.Fatal("rejected package admission changed authority/replay/frame/cache", err)
			}
		})
	}
	cert, err := f.store.CertificateForVerification(ctx, identity.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.AuthorizeCertificate(ctx, cert.DER(), at); err != nil {
		t.Fatal(err)
	}
	other := independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
	if _, err = other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: f.nextRequest(), ExpectedRevision: identity.Revision, Now: nextAt.Unix()}, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	before := operationalStoreRows(t, f.path)
	for _, body := range [][]byte{raw, next} {
		if _, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, body, nextAt); !errors.Is(err, enrollmentstate.ErrState) {
			t.Fatal("cached transport authority revived revoked identity", err)
		}
	}
	revoked, err := f.store.PackageView(ctx, identity.Approval.DeviceID, nextAt)
	if err != nil || revoked.Status != "revoked" || revoked.Snapshot == nil || revoked.Snapshot.Inventory.Quality != linuxpackages.Healthy || !revoked.ReceivedAt.Equal(at) || !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("revocation rewrote historical facts or admitted bytes", err)
	}
}

func TestIndependentPackageStoreProfileImmutableAndRecordCeiling(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	profiles := []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages}
	for _, original := range profiles {
		t.Run(original, func(t *testing.T) {
			cfg.Binding.CollectionProfile = original
			path := filepath.Join(t.TempDir(), "private", "profile.sqlite")
			s := independentEnrollmentStoreOpen(t, path, cfg, issuer)
			s.Close()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, replacement := range profiles {
				if replacement == original {
					continue
				}
				changed := cfg
				changed.Binding.CollectionProfile = replacement
				opened, err := enrollmentstore.Open(path, changed, issuer)
				if opened != nil {
					opened.Close()
				}
				if !errors.Is(err, enrollmentstore.ErrStorage) {
					t.Fatal("existing profile relabeled", original, replacement, err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("rejected profile restart mutated stored binding")
				}
			}
		})
	}
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	cfg.RecordLimit = 26
	if opened, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "over.sqlite"), cfg, issuer); !errors.Is(err, enrollmentstore.ErrStorage) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("unmeasured package identity limit admitted", err)
	}
	if 25*enrollmentstore.OperationalDeviceQuota > enrollmentstore.OperationalGlobalQuota {
		t.Fatal("pilot count bypasses global budget")
	}
}

func TestIndependentPackageHTTPConsentAuthAndAIExclusion(t *testing.T) {
	for _, httpTest := range []bool{false, true} {
		t.Run(fmt.Sprintf("http-test=%v", httpTest), func(t *testing.T) {
			h, db := operationalAPIHTTPFixture(t, httpTest, enrollmentcrypto.CollectionProfilePackages)
			session := h.session(t)
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = "GET"
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			code, body, _ := h.request(t, "/api/enrollment", nil, read)
			var advertised struct {
				CollectionProfile string `json:"collectionProfile"`
				CollectionPrivacy string `json:"collectionPrivacy"`
			}
			if code != 200 || json.Unmarshal(body, &advertised) != nil || advertised.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || advertised.CollectionPrivacy != "package_source_metadata_may_be_sensitive" {
				t.Fatal("consent advertised wrong scope")
			}
			base := `{"requestId":"` + h.f.nextRequest() + `","platform":"linux"`
			for _, suffix := range []string{`}`, `,"collectionAcknowledged":false}`, `,"collectionAcknowledged":null}`, `,"CollectionAcknowledged":true}`, `,"collectionAcknowledged":"true"}`, `,"collectionAcknowledged":true,"collectionAcknowledged":true}`, `,"collectionAcknowledged":true,"collectionProfile":"basic-readonly-v1"}`} {
				if code, _, _ := h.request(t, "/api/enrollment/invitations", []byte(base+suffix), h.browser(session)); code != 400 {
					t.Fatal("invitation bypassed explicit package consent", code)
				}
			}
			rows, err := h.f.store.Snapshots(context.Background())
			if err != nil || len(rows) != 0 {
				t.Fatal("rejected consent committed invitation", err)
			}
			code, body, _ = h.request(t, "/api/enrollment/invitations", []byte(base+`,"collectionAcknowledged":true}`), h.browser(session))
			var created struct {
				Snapshot  enrollmentstate.Snapshot `json:"snapshot"`
				Bootstrap api.EnrollmentBootstrap  `json:"bootstrap"`
			}
			if code != 201 || json.Unmarshal(body, &created) != nil || created.Snapshot.Binding.CollectionProfile != enrollmentcrypto.CollectionProfilePackages || created.Bootstrap.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
				t.Fatal("acknowledged profile changed during creation")
			}
			identity := operationalStoreActivate(t, h.f)
			path := "/api/devices/" + identity.Approval.DeviceID + "/packages"
			code, body, _ = h.request(t, path, nil, read)
			var view enrollmentstore.PackageView
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != "awaiting" || view.Snapshot != nil || !view.ServerNow.Equal(h.f.clock()) {
				t.Fatal("awaiting package API invalid")
			}
			op := operationalStoreSnapshot(h.f.clock(), "services")
			raw := packageStoreFrame(t, 1, op, packageStoreSnapshot(op, true), false)
			if _, err = h.f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, h.f.clock()); err != nil {
				t.Fatal(err)
			}
			code, body, _ = h.request(t, path, nil, read)
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != "fresh" || view.Snapshot == nil || *view.Snapshot.Release.Fields.ID != "debian" {
				t.Fatal("package API did not return accepted immutable snapshot")
			}
			var shape map[string]json.RawMessage
			if json.Unmarshal(body, &shape) != nil || len(shape) != 8 {
				t.Fatal("package API expanded exact top-level shape")
			}
			for _, field := range []string{"schemaVersion", "deviceId", "status", "serverNow", "receivedAt", "sequence", "maxAgeSeconds", "snapshot"} {
				if _, ok := shape[field]; !ok {
					t.Fatal("package API missing required member", field)
				}
			}
			for _, suffix := range []string{"?", "?fresh=true"} {
				if code, _, _ := h.request(t, path+suffix, nil, read); code != 400 {
					t.Fatal("package query altered source interpretation", code)
				}
			}
			for name, change := range map[string]func(*http.Request){"no session": func(r *http.Request) { r.Method = "GET" }, "wrong host": func(r *http.Request) { read(r); r.Host = "other.example" }, "wrong origin": func(r *http.Request) { read(r); r.Header.Set("Origin", "https://other.example") }, "cross site": func(r *http.Request) { read(r); r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
				want := 403
				if name == "no session" {
					want = 401
				}
				if code, _, _ := h.request(t, path, nil, change); code != want {
					t.Fatal("package operator boundary", name, code)
				}
			}
			if code, _, _ := h.request(t, "/api/devices/agent_"+strings.Repeat("0", 32)+"/packages", nil, read); code != 404 {
				t.Fatal("unknown package identity exposed")
			}
			for _, method := range []string{"HEAD", "PUT", "DELETE"} {
				if code, _, _ := h.request(t, path, nil, func(r *http.Request) { read(r); r.Method = method }); code != 405 {
					t.Fatal("package mutation method admitted", method, code)
				}
			}
			// A closed case store proves the instance gate runs before even reading a case.
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"synthetic-case", "unknown"} {
				code, body, _ := h.request(t, "/api/cases/"+id+"/analyze", []byte(`{"configRevision":"ignored"}`), h.browser(session))
				if code != 403 || !bytes.Contains(body, []byte("evidence_export_not_approved")) {
					t.Fatal("package profile reached case read/AI export", code)
				}
			}
			h.auth.Logout(session.Token)
			if code, _, _ := h.request(t, path, nil, read); code != 401 {
				t.Fatal("logged-out package view available")
			}
		})
	}
}

func packageStoreDenseSoftware(t *testing.T, at time.Time, target int) operational.Snapshot {
	t.Helper()
	s := operational.Empty(at, operational.ReasonSourceMissing)
	for i := range 128 {
		s.Sections.Software.Items = append(s.Sections.Software.Items, operational.Software{Name: fmt.Sprintf("fixture-package-%03d", i), Version: "1.0", Architecture: "amd64", Manager: "dpkg"})
	}
	m := &s.Sections.Software.Meta
	m.Quality = operational.Healthy
	m.Reason = operational.ReasonNone
	m.Complete = true
	m.CountExact = true
	m.ObservedCount = uint64(len(s.Sections.Software.Items))
	remaining := target - packageStoreSize(t, s)
	if remaining < 0 {
		t.Fatal("software fixture exceeds initial target")
	}
	for i := range s.Sections.Software.Items {
		item := &s.Sections.Software.Items[i]
		for _, f := range []struct {
			p   *string
			max int
		}{{&item.Version, 192}, {&item.Name, 128}} {
			n := min(remaining, f.max-len(*f.p))
			*f.p += strings.Repeat("1", n)
			remaining -= n
		}
	}
	if remaining != 0 || packageStoreSize(t, s) != target || operational.Validate(s) != nil {
		t.Fatal("cannot construct exact bounded software fixture", remaining)
	}
	return s
}
func packageStoreDensePackages(t *testing.T, op operational.Snapshot, target int) linuxpackages.Snapshot {
	t.Helper()
	s := packageStoreSnapshot(op, true)
	s.Inventory.Items = nil
	for i := range 32 {
		s.Inventory.Items = append(s.Inventory.Items, linuxpackages.PackageRow{Name: fmt.Sprintf("fixture-binary-%03d", i), Version: "1.0-1", Architecture: "amd64", SourcePackage: fmt.Sprintf("fixture-source-%03d", i), SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"})
	}
	n := uint64(len(s.Inventory.Items))
	s.Inventory.ObservedCount = &n
	s.Inventory.InstalledCount = &n
	remaining := target - packageStoreSize(t, s)
	if remaining < 0 {
		t.Fatal("package fixture exceeds initial target")
	}
	for i := range s.Inventory.Items {
		item := &s.Inventory.Items[i]
		for _, f := range []struct {
			p   *string
			max int
		}{{&item.Name, 256}, {&item.SourcePackage, 256}, {&item.Version, 192}, {&item.SourceVersion, 192}} {
			n := min(remaining, f.max-len(*f.p))
			*f.p += strings.Repeat("1", n)
			remaining -= n
		}
	}
	if remaining != 0 || packageStoreSize(t, s) != target || linuxpackages.Validate(s) != nil {
		t.Fatal("cannot construct exact bounded package fixture", remaining)
	}
	return s
}
func packageStoreRetained(samples []operational.Snapshot) enrollmentstore.LastGood {
	return enrollmentstore.LastGood{Volumes: &samples[0].Sections.Volumes, Network: &samples[1].Sections.Network, Services: &samples[2].Sections.Services, Processes: &samples[3].Sections.Processes, Events: &samples[4].Sections.Events, Software: &samples[5].Sections.Software}
}
func packageStoreCacheSize(t *testing.T, samples []operational.Snapshot) int {
	return packageStoreSize(t, struct {
		LastGood enrollmentstore.LastGood `json:"lastGood"`
	}{packageStoreRetained(samples)})
}

// Build the exact retained logical cap through six valid independent captures:
// latest baseline 32KiB + latest package component 16KiB + retained cache 80KiB.
// All padding is ordinary bounded metadata, not ignored JSON whitespace.
func packageStoreQuotaSamples(t *testing.T, start time.Time) []operational.Snapshot {
	t.Helper()
	samples := make([]operational.Snapshot, 6)
	for i, kind := range []string{"volumes", "network", "services", "processes", "events"} {
		samples[i] = operationalStoreDense(t, start.Add(time.Duration(i)*time.Second), kind)
	}
	samples[5] = packageStoreDenseSoftware(t, start.Add(5*time.Second), operational.MaxPackageFrameSnapshotBytes)
	excess := packageStoreCacheSize(t, samples) - (enrollmentstore.OperationalDeviceQuota - operational.MaxPackageFrameSnapshotBytes - linuxpackages.MaxSnapshotBytes)
	if excess < 0 {
		t.Fatal("maximum synthetic cache is below retained target", excess)
	}
	shrink := func(p *string, minLength int) {
		n := min(excess, len(*p)-minLength)
		*p = (*p)[:len(*p)-n]
		excess -= n
	}
	for i := range samples[2].Sections.Services.Items {
		item := &samples[2].Sections.Services.Items[i]
		stem := strings.TrimSuffix(item.Name, ".service")
		shrink(&stem, 4)
		item.Name = stem + ".service"
	}
	for i := range samples[0].Sections.Volumes.Items {
		shrink(&samples[0].Sections.Volumes.Items[i].MountPoint, 12)
	}
	for i := range samples[4].Sections.Events.Items {
		item := &samples[4].Sections.Events.Items[i]
		stem := strings.TrimSuffix(item.Unit, ".service")
		shrink(&stem, 4)
		item.Unit = stem + ".service"
	}
	for i := range samples[3].Sections.Processes.Items {
		shrink(&samples[3].Sections.Processes.Items[i].Name, 1)
	}
	for i := range samples[1].Sections.Network.Items {
		shrink(&samples[1].Sections.Network.Items[i].Name, 4)
	}
	if excess != 0 || packageStoreCacheSize(t, samples)+operational.MaxPackageFrameSnapshotBytes+linuxpackages.MaxSnapshotBytes != enrollmentstore.OperationalDeviceQuota {
		t.Fatal("cannot reach exact package-inclusive retained cap", excess)
	}
	for _, s := range samples {
		if operational.Validate(s) != nil || packageStoreSize(t, s) > operational.MaxPackageFrameSnapshotBytes {
			t.Fatal("quota precursor invalid or exceeds new baseline cap")
		}
	}
	return samples
}
func packageStoreBind(s operational.Snapshot, device int, seq uint64) operational.Snapshot {
	s.GenerationID = fmt.Sprintf("sample_%016x%016x", device, seq)
	for _, m := range []*operational.SectionMeta{&s.Sections.Volumes.Meta, &s.Sections.Network.Meta, &s.Sections.Services.Meta, &s.Sections.Processes.Meta, &s.Sections.Software.Meta, &s.Sections.Events.Meta} {
		m.GenerationID = s.GenerationID
	}
	return s
}
func packageStoreAssertQuota(t *testing.T, path string, wantCount int) {
	t.Helper()
	db := operationalStoreDB(t, path)
	defer db.Close()
	rows, err := db.Query("SELECT c.body,o.body FROM enrollment_credentials c JOIN enrollment_operational o USING(invitation_id) ORDER BY c.invitation_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count, total := 0, 0
	for rows.Next() {
		var credential, cache []byte
		if rows.Scan(&credential, &cache) != nil {
			t.Fatal("quota fixture read failed")
		}
		var body struct {
			Frame []byte `json:"frame"`
		}
		if json.Unmarshal(credential, &body) != nil {
			t.Fatal("credential fixture decode failed")
		}
		var frame lanstore.Frame
		if json.Unmarshal(body.Frame, &frame) != nil || frame.Operational == nil || frame.Packages == nil {
			t.Fatal("quota fixture lost components")
		}
		size := packageStoreSize(t, frame.Operational) + packageStoreSize(t, frame.Packages) + len(cache)
		if size != enrollmentstore.OperationalDeviceQuota {
			t.Fatalf("retained logical bytes %d, wanted %d", size, enrollmentstore.OperationalDeviceQuota)
		}
		total += size
		count++
	}
	if rows.Err() != nil || count != wantCount || total != wantCount*enrollmentstore.OperationalDeviceQuota || total > enrollmentstore.OperationalGlobalQuota {
		t.Fatal("aggregate logical quota mismatch", count, total, rows.Err())
	}
	t.Logf("%d distinct devices retain %d logical bytes (%d/device), bounded by %d global bytes", count, total, enrollmentstore.OperationalDeviceQuota, enrollmentstore.OperationalGlobalQuota)
}
func TestIndependentPackageStoreExactQuotaRollbackAndExpiryRecovery(t *testing.T) {
	f, identity := packageStoreFixture(t)
	ctx := context.Background()
	samples := packageStoreQuotaSamples(t, f.clock().Add(time.Second))
	var last []byte
	var receipt lanstore.Receipt
	for i, s := range samples {
		s = packageStoreBind(s, 1, uint64(i+1))
		pkg := packageStoreDensePackages(t, s, linuxpackages.MaxSnapshotBytes)
		last = packageStoreFrame(t, uint64(i+1), s, pkg, true)
		var err error
		receipt, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, last, s.CollectedAt)
		if err != nil {
			t.Fatal("valid quota precursor failed", i, err)
		}
	}
	packageStoreAssertQuota(t, f.path, 1)
	// Shift one byte from a current-only unknown-section reason into a software
	// label. The operational and package components remain exactly at their caps,
	// while the duplicated LastGood software section grows by exactly one byte.
	at := samples[5].CollectedAt.Add(time.Second)
	bounded := packageStoreBind(samples[5], 1, 7)
	bounded.CollectedAt = at
	for _, m := range []*operational.SectionMeta{&bounded.Sections.Volumes.Meta, &bounded.Sections.Network.Meta, &bounded.Sections.Services.Meta, &bounded.Sections.Processes.Meta, &bounded.Sections.Software.Meta, &bounded.Sections.Events.Meta} {
		m.ObservedAt = at
	}
	// Exchange one byte from the operational wrapper into the retained software:
	// source_missing -> not_supported saves one byte; software grows one byte.
	bounded.Sections.Volumes.Meta.Reason = operational.ReasonNotSupported
	bounded.Sections.Software.Items = append([]operational.Software{}, bounded.Sections.Software.Items...)
	index := len(bounded.Sections.Software.Items) - 1
	bounded.Sections.Software.Items[index].Name += "x"
	if packageStoreSize(t, bounded) != operational.MaxPackageFrameSnapshotBytes || operational.Validate(bounded) != nil {
		t.Fatal("one-byte quota-overrun fixture invalid")
	}
	raw := packageStoreFrame(t, 7, bounded, packageStoreDensePackages(t, bounded, linuxpackages.MaxSnapshotBytes), true)
	before := operationalStoreRows(t, f.path)
	got, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	if !errors.Is(err, enrollmentstore.ErrStorage) || got != (lanstore.Receipt{}) || !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("one-byte package-inclusive quota overrun partially committed", err)
	}
	cfg := f.store.Config()
	f.store.Close()
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	duplicate, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, last, at)
	if err != nil || !duplicate.Duplicate || duplicate.Sequence != receipt.Sequence || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) || !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("quota rejection advanced replay or changed retained bytes across reopen", err)
	}
	recoveredAt := at.Add(enrollmentstore.OperationalRetention)
	recovered := packageStoreDenseSoftware(t, recoveredAt, operational.MaxPackageFrameSnapshotBytes)
	recovered = packageStoreBind(recovered, 1, 7)
	raw = packageStoreFrame(t, 7, recovered, packageStoreDensePackages(t, recovered, linuxpackages.MaxSnapshotBytes), true)
	if _, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, recoveredAt); err != nil {
		t.Fatal("expiry did not release retained-only quota atomically", err)
	}
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, recoveredAt)
	if err != nil || view.LastGood.Software == nil || view.LastGood.Services != nil || view.LastGood.Processes != nil || view.LastGood.Volumes != nil || view.LastGood.Network != nil || view.LastGood.Events != nil {
		t.Fatal("expired cache survived quota recovery", err)
	}
}

// The request body is rebuilt only from already-staged exact fixture bytes. A
// second attempt does not refresh a signature, collection time or generation.
func packageStoreIngress(t *testing.T, f *independentServiceFixture, identity enrollmentstate.Snapshot) func([]byte, uint64, time.Time) (lanstore.Receipt, error) {
	t.Helper()
	ctx := context.Background()
	cert, err := f.store.CertificateForVerification(ctx, identity.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{cert.DER()}, PrivateKey: f.key}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	profile := f.store.Config().Binding.Profile
	origin := "https://" + server.Listener.Addr().String()
	if profile == "http-test" {
		origin = "http://" + server.Listener.Addr().String()
	}
	ingress, err := enrollmenttransport.New(f.store, f.issuer.IssuerDER(), origin)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = ingress
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	if profile == "tls" {
		ca := makeReviewCA(t)
		serverPair, _ := makeReviewLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Time{})
		server.TLS, err = ingress.TLSConfig(serverPair)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca.pem) {
			t.Fatal("fixture server trust failed")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}
		server.StartTLS()
	} else {
		server.Start()
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(raw []byte, sequence uint64, at time.Time) (lanstore.Receipt, error) {
		var request *http.Request
		var err error
		if profile == "tls" {
			request, err = http.NewRequestWithContext(ctx, http.MethodPost, origin+signedhttp.Path, bytes.NewReader(raw))
			if err == nil {
				request.Header.Set("Content-Type", "application/json")
			}
		} else {
			request, err = signedhttp.NewSignedRequest(ctx, origin, pair, sequence, at, raw)
		}
		if err != nil {
			return lanstore.Receipt{}, err
		}
		response, err := client.Do(request)
		if err != nil {
			return lanstore.Receipt{}, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			return lanstore.Receipt{}, err
		}
		var receipt lanstore.Receipt
		if response.StatusCode == http.StatusOK {
			if err = json.Unmarshal(body, &receipt); err != nil {
				return lanstore.Receipt{}, err
			}
			return receipt, nil
		}
		var problem struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if response.StatusCode == http.StatusTooManyRequests && response.Header.Get("Retry-After") == "15" && json.Unmarshal(body, &problem) == nil && problem.Error.Code == "storage_busy" && problem.Error.Message == "Agent telemetry could not be accepted." {
			return lanstore.Receipt{}, enrollmentstore.ErrBusy
		}
		return lanstore.Receipt{}, fmt.Errorf("package ingress returned unexpected status %d", response.StatusCode)
	}
}
func TestIndependentPackageStoreDenseCapacityAndActualIngress(t *testing.T) {
	for _, shared := range []bool{true, false} {
		topology := "cross-handle"
		if shared {
			topology = "same-handle"
		}
		for _, profile := range []string{"tls", "http-test"} {
			t.Run(topology+"/"+profile, func(t *testing.T) {
				f := packageStoreFresh(t, operationalStoreWallClockFixture(t, profile))
				ctx := context.Background()
				identities := make([]enrollmentstate.Snapshot, 0, 25)
				for len(identities) < 25 {
					var err error
					f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
					if err != nil {
						t.Fatal(err)
					}
					identities = append(identities, operationalStoreActivate(t, f))
				}
				// Fix collection times before dense population; ordinary source age limits
				// still apply to every frame. Six originals contribute to each LastGood.
				samples := packageStoreQuotaSamples(t, time.Now().UTC().Truncate(time.Second))
				var lastFrame []byte
				for sequence, sample := range samples {
					for device, identity := range identities {
						bound := packageStoreBind(sample, device+1, uint64(sequence+1))
						raw := packageStoreFrame(t, uint64(sequence+1), bound, packageStoreDensePackages(t, bound, linuxpackages.MaxSnapshotBytes), true)
						if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, sample.CollectedAt); err != nil {
							t.Fatal("25-device dense population failed", sequence, device, err)
						}
						if device == 1 {
							lastFrame = raw
						}
					}
				}
				operationalStoreAssertDistinctFrames(t, f.path, 25)
				packageStoreAssertQuota(t, f.path, 25)
				reopenStart := time.Now()
				other := independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
				reloadDuration := time.Since(reopenStart)
				third := f.store
				if shared {
					other.Close()
					other = f.store
				} else {
					third = independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
				}
				send := packageStoreIngress(t, f, identities[1])
				// Advancing capture metadata does not alter any component or retained budget.
				if delay := time.Until(samples[5].CollectedAt.Add(time.Second)); delay > 0 {
					time.Sleep(delay)
				}
				at := time.Now().UTC().Truncate(time.Second)
				op := packageStoreDenseSoftware(t, at, operational.MaxPackageFrameSnapshotBytes)
				op = packageStoreBind(op, 2, 7)
				raw := packageStoreFrame(t, 7, op, packageStoreDensePackages(t, op, linuxpackages.MaxSnapshotBytes), true)
				before := make([][]byte, 3)
				for n := range 3 {
					before[n] = operationalStoreIdentityRows(t, f.path, identities[n].InvitationID)
				}
				var receipt lanstore.Receipt
				perform := func(n int) error {
					var err error
					switch n {
					case 0:
						_, err = other.PackageView(ctx, identities[0].Approval.DeviceID, at)
					case 1:
						receipt, err = send(raw, 7, at)
					case 2:
						_, err = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identities[2].InvitationID, RequestID: independentEnrollmentID("request", 987659), ExpectedRevision: identities[2].Revision, Now: at.Unix()}, State: enrollmentstate.Revoked})
					}
					return err
				}
				start := make(chan struct{})
				var wg sync.WaitGroup
				durations := make([]time.Duration, 3)
				errs := make([]error, 3)
				for n := range 3 {
					wg.Add(1)
					go func(n int) {
						defer wg.Done()
						<-start
						begin := time.Now()
						errs[n] = perform(n)
						durations[n] = time.Since(begin)
					}(n)
				}
				close(start)
				wg.Wait()
				t.Logf("25 distinct package identities at exact 128 KiB/device, %d-byte frames, %s %s: reload=%s read=%s (%v) ingress=%s (%v) revoke=%s (%v)", len(raw), topology, profile, reloadDuration, durations[0], errs[0], durations[1], errs[1], durations[2], errs[2])
				for n, err := range errs {
					if operationalStoreRaceBusyRetry(t, operationalStoreRaceInstrumented && !shared, err, f, identities[n], before[n]) {
						if err := perform(n); err != nil {
							t.Fatal("exact post-contention package retry failed", err)
						}
					}
				}
				if receipt.AgentID != identities[1].Approval.DeviceID || receipt.Sequence != 7 || receipt.Duplicate || !receipt.CollectedAt.Equal(at) {
					t.Fatal("actual package ingress receipt does not bind committed frame")
				}
				view, err := f.store.PackageView(ctx, identities[1].Approval.DeviceID, at)
				if err != nil || view.Sequence == nil || *view.Sequence != 7 || view.Snapshot == nil || view.Snapshot.GenerationID != op.GenerationID {
					t.Fatal("ingress package component did not commit", err)
				}
				old := operationalStoreRows(t, f.path)
				duplicate, err := send(raw, 7, at)
				if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) || !bytes.Equal(old, operationalStoreRows(t, f.path)) {
					t.Fatal("actual exact retry changed package frame/receipt/cache", err)
				}
				if _, err := f.store.SaveObservation(ctx, identities[1].InvitationID, identities[1].Issuance.CertificateHash, lastFrame, time.Now().UTC()); (!errors.Is(err, lanstore.ErrReplay) && !errors.Is(err, lanstore.ErrStale)) || !bytes.Equal(old, operationalStoreRows(t, f.path)) {
					t.Fatal("historical replaced frame accepted after latest ingress", err)
				}
				revoked, err := f.store.Get(ctx, identities[2].InvitationID)
				if err != nil || revoked.State != enrollmentstate.Revoked {
					t.Fatal("concurrent revoke failed", err)
				}
				if _, err := f.service.CreateInvitation(ctx, f.nextRequest(), "linux"); !errors.Is(err, enrollmentstate.ErrCapacity) {
					t.Fatal("revoked tombstone no longer consumes 25-device cap", err)
				}
				packageStoreAssertQuota(t, f.path, 25)
			})
		}
	}
}

func TestIndependentPackageAISourcePolicyRejectsEveryManagedProvenance(t *testing.T) {
	for _, location := range []string{"case", "case evidence", "selected available evidence"} {
		t.Run(location, func(t *testing.T) {
			c := operationalAPIReviewCase("fixture-package-case", "", "")
			available := append(c.Evidence[:0:0], c.Evidence...)
			if _, err := analysis.BuildPacket(c, available); err != nil {
				t.Fatal("baseline synthetic packet invalid", err)
			}
			switch location {
			case "case":
				c.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
			case "case evidence":
				c.Evidence[0].CollectionProfile = enrollmentcrypto.CollectionProfilePackages
			case "selected available evidence":
				available[0].CollectionProfile = enrollmentcrypto.CollectionProfilePackages
			}
			packet, err := analysis.BuildPacket(c, available)
			if !errors.Is(err, analysis.ErrInvalidPacket) || packet.Case.Title != "" || len(packet.Evidence) != 0 {
				t.Fatal("package-derived text entered AI packet", err)
			}
		})
	}
}
func TestIndependentPackageHTTPLegacyUnknownAndStorageFault(t *testing.T) {
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages} {
		t.Run(profile, func(t *testing.T) {
			h, _ := operationalAPIHTTPFixture(t, true, profile)
			identity := operationalStoreActivate(t, h.f)
			session := h.session(t)
			read := func(r *http.Request) {
				h.browser(session)(r)
				r.Method = "GET"
				r.Header.Del("Origin")
				r.Header.Del("X-CSRF-Token")
			}
			path := "/api/devices/" + identity.Approval.DeviceID + "/packages"
			code, body, _ := h.request(t, path, nil, read)
			var view enrollmentstore.PackageView
			expected := "not_configured"
			if profile == enrollmentcrypto.CollectionProfilePackages {
				expected = "awaiting"
			}
			if code != 200 || json.Unmarshal(body, &view) != nil || view.Status != expected || view.Snapshot != nil || view.Sequence != nil || view.ReceivedAt != nil {
				t.Fatal("old/awaiting profile fabricated package facts", code)
			}
			if err := h.f.store.Close(); err != nil {
				t.Fatal(err)
			}
			code, body, _ = h.request(t, path, nil, read)
			if code != 500 || bytes.Contains(body, []byte("not_configured")) || bytes.Contains(body, []byte("awaiting")) || bytes.Contains(body, []byte(h.f.path)) {
				t.Fatal("storage failure became missing package data or leaked path", code)
			}
		})
	}
}

func TestIndependentPackageHTTPBusySharesReadAdmissionAndKeepsRevocationSlot(t *testing.T) {
	h, _ := operationalAPIHTTPFixture(t, true, enrollmentcrypto.CollectionProfilePackages)
	identity := operationalStoreActivate(t, h.f)
	session := h.session(t)
	ctx := context.Background()
	db := operationalStoreDB(t, h.f.path)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	start := make(chan struct{})
	results := make(chan error, 32)
	var wg sync.WaitGroup
	for n := range 32 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			copied := *h.f.store
			var err error
			if n%2 == 0 {
				_, err = copied.PackageView(ctx, identity.Approval.DeviceID, h.f.clock())
			} else {
				_, err = copied.OperationalView(ctx, identity.Approval.DeviceID, h.f.clock())
			}
			results <- err
		}(n)
	}
	close(start)
	for range 31 {
		select {
		case err := <-results:
			if !errors.Is(err, enrollmentstore.ErrOperationalBusy) {
				t.Fatal("mixed package/baseline readers bypassed shared admission", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("mixed read queue grew behind database lock")
		}
	}
	read := func(r *http.Request) {
		h.browser(session)(r)
		r.Method = "GET"
		r.Header.Del("Origin")
		r.Header.Del("X-CSRF-Token")
	}
	code, body, headers := h.request(t, "/api/devices/"+identity.Approval.DeviceID+"/packages", nil, read)
	var problem struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if code != 429 || headers.Get("Retry-After") != "2" || json.Unmarshal(body, &problem) != nil || problem.Error.Code != "storage_busy" || problem.Error.Message != "Stored package observations are busy; retry shortly." {
		t.Fatal("package read contention did not use fixed 429 contract", code)
	}
	revoked := make(chan error, 1)
	requestID := h.f.nextRequest()
	go func() {
		_, err := h.f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: requestID, ExpectedRevision: identity.Revision, Now: h.f.clock().Unix() + 1}, State: enrollmentstate.Revoked})
		revoked <- err
	}()
	if _, err = conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-revoked:
		if err != nil {
			t.Fatal("operator revoke lost spare store slot", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoke did not complete after mixed read lock released")
	}
	select {
	case err := <-results:
		if err != nil {
			t.Fatal("single admitted mixed read failed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("single admitted mixed read did not finish")
	}
	wg.Wait()
	view, err := h.f.store.PackageView(ctx, identity.Approval.DeviceID, h.f.clock().Add(time.Second))
	if err != nil || view.Status != "revoked" {
		t.Fatal("package view missed current revoke after contention", err)
	}
}

func TestIndependentPackageStoreFreshReceiptCannotRefreshCaptureAge(t *testing.T) {
	f, identity := packageStoreFixture(t)
	ctx := context.Background()
	collected := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(collected, "")
	raw := packageStoreFrame(t, 1, op, packageStoreSnapshot(op, true), false)
	received := collected.Add(lanstore.SampleMaxAge - time.Second)
	receipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, received)
	if err != nil || !receipt.ReceivedAt.Equal(received) {
		t.Fatal("delayed valid source fixture rejected", err)
	}
	before := operationalStoreRows(t, f.path)
	for _, tc := range []struct {
		now     time.Time
		status  string
		visible bool
	}{
		{received, "fresh", true},
		{received.Add(2 * time.Second), "stale", true},
		{received.Add(-time.Nanosecond), "stale", true},
		{collected.Add(enrollmentstore.OperationalRetention - time.Nanosecond), "stale", true},
		{collected.Add(enrollmentstore.OperationalRetention), "unavailable", false},
	} {
		view, err := f.store.PackageView(ctx, identity.Approval.DeviceID, tc.now)
		if err != nil || view.Status != tc.status || (view.Snapshot != nil) != tc.visible || view.ReceivedAt == nil || !view.ReceivedAt.Equal(received) || view.Sequence == nil || *view.Sequence != 1 {
			t.Fatal("fresh receipt or future receipt changed original-source age policy", tc.status, err)
		}
		if view.Snapshot != nil && (!view.Snapshot.CollectedAt.Equal(collected) || view.Snapshot.Inventory.Quality != linuxpackages.Healthy) {
			t.Fatal("age view rewrote source time or quality")
		}
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("source age projection rewrote retained exact frame or receipt")
	}
}
