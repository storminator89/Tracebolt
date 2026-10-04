package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
	"localrmm/internal/signedhttp"
)

// These integration checks use only synthetic observations, in-memory ephemeral
// fixture keys and disposable databases. They never collect host inventories,
// invoke OS providers, alter systemd, or contact a remote service.
func operationalStoreFixture(t *testing.T) (*independentServiceFixture, enrollmentstate.Snapshot) {
	t.Helper()
	f := independentServiceNew(t, false)
	cfg := f.store.Config()
	if err := f.store.Close(); err != nil {
		t.Fatal("fixture close failed")
	}
	cfg.Binding.CollectionProfile = operational.CollectionProfile
	f.path = filepath.Join(t.TempDir(), "private", "operations.sqlite")
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	var err error
	f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
	if err != nil {
		t.Fatal("operational fixture service failed", err)
	}
	return f, operationalStoreActivate(t, f)
}

func operationalStoreActivate(t *testing.T, f *independentServiceFixture) enrollmentstate.Snapshot {
	t.Helper()
	created, err := f.service.CreateInvitation(context.Background(), f.nextRequest(), "linux")
	if err != nil {
		t.Fatal("fixture invitation failed", err)
	}
	cClaim, err := f.service.Challenge("192.0.2.40", created.Snapshot().InvitationID, strings.Replace(f.nextRequest(), "request_", "claim_", 1), "claim")
	if err != nil {
		t.Fatal("fixture claim challenge failed", err)
	}
	requestClaim := f.nextRequest()
	messageClaim, err := enrollmentcrypto.ClaimSigningMessage(cClaim.Context, requestClaim, f.csr, created.Secret(), f.clock())
	if err != nil {
		t.Fatal("fixture claim message failed", err)
	}
	bodyClaim, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": cClaim.Context.ManagerInstanceID, "profile": cClaim.Context.Profile, "origin": cClaim.Context.Origin, "collectionProfile": cClaim.Context.CollectionProfile, "invitationId": cClaim.Context.InvitationID, "claimId": cClaim.Context.ClaimID, "requestId": requestClaim, "challenge": cClaim.Context.Challenge, "invitationSecret": created.Secret(), "csr": base64.RawStdEncoding.EncodeToString(f.csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, messageClaim))})
	if err != nil {
		t.Fatal("fixture claim body failed", err)
	}
	s, err := f.service.Claim(context.Background(), cClaim.Context.Challenge, bodyClaim)
	if err != nil {
		t.Fatal("fixture ordinary claim failed", err)
	}
	s, err = f.service.Approve(context.Background(), s.InvitationID, f.nextRequest(), s.Claim.KeyFingerprint, s.Revision)
	if err != nil {
		t.Fatal("fixture approval failed", err)
	}
	s, err = f.status(t, s)
	if err != nil || s.State != enrollmentstate.Issued {
		t.Fatal("ordinary fixture issuance failed", err)
	}
	cert, err := f.store.CertificateForVerification(context.Background(), s.InvitationID)
	if err != nil {
		t.Fatal("fixture certificate lookup failed", err)
	}
	c := f.challenge(t, s, "activation")
	request := f.nextRequest()
	intent := cert.Intent()
	message, err := enrollmentcrypto.ActivationSigningMessage(c.Context, intent, request, cert.CertificateHash(), f.clock())
	if err != nil {
		t.Fatal("fixture activation message failed", err)
	}
	raw, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": intent.ManagerInstanceID, "profile": intent.Profile, "origin": intent.Origin, "deviceId": intent.DeviceID, "intentId": intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	if err != nil {
		t.Fatal("fixture activation encoding failed")
	}
	s, err = f.service.Activate(context.Background(), c.Context.Challenge, raw)
	if err != nil || s.State != enrollmentstate.Activated {
		t.Fatal("ordinary fixture activation failed", err)
	}
	return s
}

func operationalStoreSnapshot(at time.Time, sections string) operational.Snapshot {
	s := operational.Empty(at, operational.ReasonSourceMissing)
	healthy := func(m *operational.SectionMeta) {
		m.Quality = operational.Healthy
		m.Reason = operational.ReasonNone
		m.Complete = true
		m.CountExact = true
		m.ObservedCount = 1
	}
	if strings.Contains(sections, "services") {
		healthy(&s.Sections.Services.Meta)
		s.Sections.Services.Items = []operational.Service{{Name: "fixture.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}}
	}
	if strings.Contains(sections, "software") {
		healthy(&s.Sections.Software.Meta)
		s.Sections.Software.Items = []operational.Software{{Name: "fixture-package", Version: "1.0", Architecture: "amd64", Manager: "dpkg"}}
	}
	return s
}

func operationalStoreFrame(t *testing.T, seq uint64, at time.Time, op *operational.Snapshot) []byte {
	t.Helper()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Disposable fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture OS", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at, Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	version := lanstore.FrameVersion
	if op != nil {
		version = lanstore.FrameOperationalVersion
	}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: version, Sequence: seq, Observation: b, Operational: op})
	if err != nil {
		t.Fatal("fixture frame encoding failed")
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal("synthetic frame invalid", err)
	}
	return raw
}

func operationalStoreDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("disposable database read failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func operationalStoreRows(t *testing.T, path string) []byte {
	t.Helper()
	db := operationalStoreDB(t, path)
	defer db.Close()
	var out bytes.Buffer
	for _, table := range []string{"enrollment_state", "enrollment_credentials", "enrollment_operational"} {
		column, order := "body", "invitation_id"
		if table == "enrollment_state" {
			column, order = "ledger", "id"
		}
		rows, err := db.Query("SELECT " + column + " FROM " + table + " ORDER BY " + order)
		if err != nil {
			t.Fatal("fixture logical read failed")
		}
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil {
				t.Fatal("fixture row read failed")
			}
			out.Write(raw)
			out.WriteByte('\n')
		}
		if rows.Err() != nil {
			t.Fatal("fixture row iteration failed")
		}
		rows.Close()
	}
	return out.Bytes()
}

func TestIndependentOperationalStoreMixedProvenanceExpiryAndExactRetry(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	first := operationalStoreSnapshot(at, "services")
	raw := operationalStoreFrame(t, 1, at, &first)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal(err)
	}
	nextAt := at.Add(time.Minute)
	second := operationalStoreSnapshot(nextAt, "software")
	next := operationalStoreFrame(t, 2, nextAt, &second)
	receipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt)
	if err != nil {
		t.Fatal(err)
	}
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, nextAt)
	if err != nil || view.Status != "fresh" || view.Snapshot == nil || view.LastGood.Services == nil || view.LastGood.Software == nil {
		t.Fatal("mixed view unavailable", err)
	}
	if view.LastGood.Services.Meta.GenerationID != first.GenerationID || !view.LastGood.Services.Meta.ObservedAt.Equal(at) || view.LastGood.Software.Meta.GenerationID != second.GenerationID || !view.LastGood.Software.Meta.ObservedAt.Equal(nextAt) || view.Snapshot.GenerationID != second.GenerationID {
		t.Fatal("per-section original provenance was rewritten")
	}
	if view.LastGood.Services.Meta.Quality != "stale" || view.Snapshot.Sections.Services.Meta.Quality != operational.Unknown {
		t.Fatal("unknown latest section became green")
	}
	before := operationalStoreRows(t, f.path)
	cfg := f.store.Config()
	f.store.Close()
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	duplicate, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt.Add(3*time.Minute))
	if err != nil || !duplicate.Duplicate || duplicate.Sequence != receipt.Sequence || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) || !duplicate.CollectedAt.Equal(receipt.CollectedAt) {
		t.Fatal("restart retry did not preserve exact original receipt", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("duplicate refreshed durable age or cache")
	}
	boundary := at.Add(enrollmentstore.OperationalRetention)
	view, err = f.store.OperationalView(ctx, identity.Approval.DeviceID, boundary)
	if err != nil || view.Status != "stale" || view.LastGood.Services != nil || view.LastGood.Software == nil || view.Snapshot == nil {
		t.Fatal("section expiry ignored original times", err)
	}
	view, err = f.store.OperationalView(ctx, identity.Approval.DeviceID, nextAt.Add(enrollmentstore.OperationalRetention))
	if err != nil || view.Status != "unavailable" || view.Snapshot != nil || view.LastGood.Services != nil || view.LastGood.Software != nil {
		t.Fatal("24-hour visibility boundary failed", err)
	}
	before = operationalStoreRows(t, f.path)
	f.store.Close()
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	duplicate, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt.Add(enrollmentstore.OperationalRetention+time.Second))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(nextAt) {
		t.Fatal("retained authenticated raw frame lost after cache expiry", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("post-expiry retry resurrected cache")
	}
}

func TestIndependentOperationalStoreRejectedAdmissionsPreserveRows(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(at, "services")
	raw := operationalStoreFrame(t, 1, at, &op)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal(err)
	}
	nextAt := at.Add(time.Second)
	fresh := operationalStoreSnapshot(nextAt, "software")
	next := operationalStoreFrame(t, 2, nextAt, &fresh)
	old := operationalStoreFrame(t, 2, nextAt, &op)
	sameGeneration := fresh
	sameGeneration.GenerationID = op.GenerationID
	for _, m := range []*operational.SectionMeta{&sameGeneration.Sections.Volumes.Meta, &sameGeneration.Sections.Network.Meta, &sameGeneration.Sections.Services.Meta, &sameGeneration.Sections.Processes.Meta, &sameGeneration.Sections.Software.Meta, &sameGeneration.Sections.Events.Meta} {
		m.GenerationID = op.GenerationID
	}
	cases := []struct {
		name  string
		frame []byte
		hash  string
		at    time.Time
		want  error
	}{
		{"wrong certificate", next, strings.Repeat("a", 64), nextAt, enrollmentstate.ErrProof},
		{"basic frame", operationalStoreFrame(t, 2, nextAt, nil), identity.Issuance.CertificateHash, nextAt, enrollmentstate.ErrProof},
		{"old operational time", old, identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"reused latest generation", operationalStoreFrame(t, 2, nextAt, &sameGeneration), identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"new payload old sequence", operationalStoreFrame(t, 1, nextAt, &fresh), identity.Issuance.CertificateHash, nextAt, lanstore.ErrReplay},
		{"late sample", next, identity.Issuance.CertificateHash, nextAt.Add(3 * time.Minute), lanstore.ErrStale},
		{"backward receipt", next, identity.Issuance.CertificateHash, at.Add(-time.Nanosecond), enrollmentstate.ErrInvalid},
		{"duplicate JSON member", bytes.Replace(next, []byte(`"sequence":2`), []byte(`"sequence":2,"sequence":2`), 1), identity.Issuance.CertificateHash, nextAt, lanstore.ErrFrame},
		{"missing operational field", bytes.Replace(next, []byte(`"durationMs":0,`), nil, 1), identity.Issuance.CertificateHash, nextAt, lanstore.ErrFrame},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := operationalStoreRows(t, f.path)
			if _, err := f.store.SaveObservation(ctx, identity.InvitationID, c.hash, c.frame, c.at); !errors.Is(err, c.want) {
				t.Fatal("unexpected rejection", err)
			}
			if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
				t.Fatal("rejected admission altered durable rows")
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before := operationalStoreRows(t, f.path)
	if _, err := f.store.SaveObservation(canceled, identity.InvitationID, identity.Issuance.CertificateHash, next, nextAt); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled admission accepted", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("canceled admission mutated rows")
	}
}

func TestIndependentOperationalStoreRevocationWinsRecheck(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(at, "services")
	raw := operationalStoreFrame(t, 1, at, &op)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal(err)
	}
	cert, err := f.store.CertificateForVerification(ctx, identity.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeCertificate(ctx, cert.DER(), at); err != nil {
		t.Fatal("fixture preauthorization failed", err)
	}
	other := independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
	revoke := enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: f.nextRequest(), ExpectedRevision: identity.Revision, Now: at.Add(time.Second).Unix()}, State: enrollmentstate.Revoked}
	if _, err := other.Terminate(ctx, revoke); err != nil {
		t.Fatal(err)
	}
	before := operationalStoreRows(t, f.path)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at.Add(2*time.Second)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("previous authorization accepted revoked exact retry", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("revoked retry mutated state")
	}
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, at.Add(2*time.Second))
	if err != nil || view.Status != "revoked" || view.Snapshot == nil || view.Snapshot.Sections.Services.Meta.Quality != "stale" || !view.ReceivedAt.Equal(at) {
		t.Fatal("revoked read lost explicit state or rewrote freshness", err)
	}
}

func TestIndependentOperationalStoreStrictReloadAndFailurePreservation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *sql.DB, string)
	}{
		{"missing cache", func(t *testing.T, db *sql.DB, id string) {
			if _, err := db.Exec("DELETE FROM enrollment_operational WHERE invitation_id=?", id); err != nil {
				t.Fatal(err)
			}
		}},
		{"orphan cache", func(t *testing.T, db *sql.DB, id string) {
			if _, err := db.Exec("UPDATE enrollment_operational SET invitation_id=? WHERE invitation_id=?", independentEnrollmentID("invite", 9876), id); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown cache member", func(t *testing.T, db *sql.DB, id string) {
			operationalStoreMutateCache(t, db, id, func(raw []byte) []byte { return append([]byte(`{"extra":0,`), raw[1:]...) })
		}},
		{"duplicate cache member", func(t *testing.T, db *sql.DB, id string) {
			operationalStoreMutateCache(t, db, id, func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"volumes":null`), []byte(`"volumes":null,"volumes":null`), 1)
			})
		}},
		{"missing cache member", func(t *testing.T, db *sql.DB, id string) {
			operationalStoreMutateCache(t, db, id, func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"volumes":null,`), nil, 1) })
		}},
		{"invalid retained section", func(t *testing.T, db *sql.DB, id string) {
			operationalStoreMutateCache(t, db, id, func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"quality":"healthy"`), []byte(`"quality":"stale"`), 1)
			})
		}},
		{"unknown schema object", func(t *testing.T, db *sql.DB, id string) {
			if _, err := db.Exec("CREATE TABLE unrecognized(value INTEGER)"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, identity := operationalStoreFixture(t)
			at := f.clock().Add(time.Second)
			op := operationalStoreSnapshot(at, "services")
			raw := operationalStoreFrame(t, 1, at, &op)
			if _, err := f.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
				t.Fatal(err)
			}
			db := operationalStoreDB(t, f.path)
			c.mutate(t, db, identity.InvitationID)
			db.Close()
			if _, err := f.store.OperationalView(context.Background(), identity.Approval.DeviceID, at); !errors.Is(err, enrollmentstore.ErrStorage) {
				t.Fatal("live handle reused invalid cached authority", err)
			}
			cfg := f.store.Config()
			f.store.Close()
			before, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := enrollmentstore.Open(f.path, cfg, f.issuer.IssuerDER())
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, enrollmentstore.ErrStorage) {
				t.Fatal("incomplete or ambiguous store reopened", err)
			}
			after, err := os.ReadFile(f.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected reopen modified fixture database")
			}
		})
	}
}

func operationalStoreMutateCache(t *testing.T, db *sql.DB, id string, change func([]byte) []byte) {
	t.Helper()
	var raw []byte
	if err := db.QueryRow("SELECT body FROM enrollment_operational WHERE invitation_id=?", id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE enrollment_operational SET body=? WHERE invitation_id=?", change(raw), id); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentOperationalStoreProfileAndRecordCeilings(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	for _, original := range []string{"basic-readonly-v1", operational.CollectionProfile} {
		t.Run(original, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private", "profile.sqlite")
			cfg.Binding.CollectionProfile = original
			s := independentEnrollmentStoreOpen(t, path, cfg, issuer)
			s.Close()
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			other := cfg
			if original == operational.CollectionProfile {
				other.Binding.CollectionProfile = "basic-readonly-v1"
			} else {
				other.Binding.CollectionProfile = operational.CollectionProfile
			}
			swapped, err := enrollmentstore.Open(path, other, issuer)
			if swapped != nil {
				swapped.Close()
			}
			if !errors.Is(err, enrollmentstore.ErrStorage) {
				t.Fatal("profile was silently rebound", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected profile switch altered store")
			}
		})
	}
	cfg.Binding.CollectionProfile = operational.CollectionProfile
	cfg.RecordLimit = 26
	if s, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "excess.sqlite"), cfg, issuer); !errors.Is(err, enrollmentstore.ErrStorage) {
		if s != nil {
			s.Close()
		}
		t.Fatal("unreviewed operational identity cap accepted", err)
	}
	if 25*enrollmentstore.OperationalDeviceQuota > enrollmentstore.OperationalGlobalQuota {
		t.Fatal("configured record/device budget exceeds global quota")
	}
}

func operationalStoreDense(t *testing.T, at time.Time, kind string) operational.Snapshot {
	t.Helper()
	s := operational.Empty(at, operational.ReasonSourceMissing)
	zero, one := uint64(0), uint64(1)
	percent := 100.0
	cpu := 0.0
	var meta *operational.SectionMeta
	switch kind {
	case "volumes":
		for i := 0; i < operational.VolumeLimit; i++ {
			s.Sections.Volumes.Items = append(s.Sections.Volumes.Items, operational.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: fmt.Sprintf("/srv/%03d/", i) + strings.Repeat("v", 151), Filesystem: "ext4", Kind: "local", TotalBytes: &one, AvailableBytes: &zero, UsedPercent: &percent, MeasurementQuality: operational.Healthy, MeasurementReason: operational.ReasonNone})
		}
		meta = &s.Sections.Volumes.Meta
	case "network":
		for i := 0; i < operational.NetworkLimit; i++ {
			s.Sections.Network.Items = append(s.Sections.Network.Items, operational.NetworkInterface{Name: fmt.Sprintf("n%03d", i) + strings.Repeat("x", 60), State: "up", MTU: &one, RXBytes: &one, TXBytes: &one, RXErrors: &zero, TXErrors: &zero, IPv4Count: &zero, IPv6Count: &zero})
		}
		meta = &s.Sections.Network.Meta
	case "services":
		for i := 0; i < operational.ServiceLimit; i++ {
			s.Sections.Services.Items = append(s.Sections.Services.Items, operational.Service{Name: fmt.Sprintf("f%03d", i) + strings.Repeat("s", 116) + ".service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"})
		}
		meta = &s.Sections.Services.Meta
	case "processes":
		for i := 0; i < operational.ProcessLimit; i++ {
			s.Sections.Processes.Items = append(s.Sections.Processes.Items, operational.Process{PID: uint64(i + 1), ParentPID: &zero, Name: strings.Repeat("p", 64), State: "sleeping", RSSBytes: &one, CPUTimeSeconds: &cpu, Threads: &one})
		}
		meta = &s.Sections.Processes.Meta
	case "software":
		for i := 0; i < operational.SoftwareLimit; i++ {
			s.Sections.Software.Items = append(s.Sections.Software.Items, operational.Software{Name: fmt.Sprintf("p%03d", i) + strings.Repeat("p", 124), Version: strings.Repeat("1", 192), Architecture: strings.Repeat("a", 32), Manager: "dpkg"})
		}
		meta = &s.Sections.Software.Meta
	case "events":
		for i := 0; i < operational.EventLimit; i++ {
			s.Sections.Events.Items = append(s.Sections.Events.Items, operational.Event{Source: "systemd-journal", Unit: fmt.Sprintf("f%03d", i) + strings.Repeat("e", 116) + ".service", Priority: 3, MessageID: fmt.Sprintf("%032x", i), Count: 1, FirstSeen: at.Add(-time.Minute), LastSeen: at})
		}
		meta = &s.Sections.Events.Meta
	default:
		t.Fatal("unsupported synthetic dense section")
	}
	meta.Quality = operational.Healthy
	meta.Reason = operational.ReasonNone
	meta.Complete = true
	meta.CountExact = true
	meta.ObservedCount = uint64(meta.ItemLimit)
	// Only software reaches the wire ceiling before its count cap. Keep a fully
	// valid synthetic exact enumeration, without relaxing the real validators.
	if kind == "software" {
		for len(s.Sections.Software.Items) > 0 {
			if operational.Validate(s) == nil {
				break
			}
			s.Sections.Software.Items = s.Sections.Software.Items[:len(s.Sections.Software.Items)-1]
			meta.ObservedCount = uint64(len(s.Sections.Software.Items))
		}
	}
	if err := operational.Validate(s); err != nil {
		t.Fatal("dense synthetic section invalid", kind, err)
	}
	return s
}

func TestIndependentOperationalStoreQuotaRollbackAndExpiryRecovery(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	start := f.clock().Add(time.Second)
	var last []byte
	var lastReceipt lanstore.Receipt
	sections := []string{"services", "processes", "volumes", "network", "events"}
	for i, section := range sections {
		at := start.Add(time.Duration(i) * time.Second)
		op := operationalStoreDense(t, at, section)
		raw := operationalStoreFrame(t, uint64(i+1), at, &op)
		var err error
		lastReceipt, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
		if err != nil {
			t.Fatal("bounded precursor observation failed", section, err)
		}
		last = raw
	}
	at := start.Add(time.Minute)
	over := operationalStoreDense(t, at, "software")
	raw := operationalStoreFrame(t, 6, at, &over)
	before := operationalStoreRows(t, f.path)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); !errors.Is(err, enrollmentstore.ErrStorage) {
		t.Fatal("aggregate device quota was not enforced", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("quota rejection partially committed replay, raw frame, or retained cache")
	}
	cfg := f.store.Config()
	f.store.Close()
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	duplicate, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, last, at)
	if err != nil || !duplicate.Duplicate || duplicate.Sequence != lastReceipt.Sequence || !duplicate.ReceivedAt.Equal(lastReceipt.ReceivedAt) {
		t.Fatal("quota rejection advanced replay floor across reopen", err)
	}
	at = start.Add(enrollmentstore.OperationalRetention + time.Minute)
	recovered := operationalStoreDense(t, at, "software")
	raw = operationalStoreFrame(t, 6, at, &recovered)
	receipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at)
	if err != nil || receipt.Sequence != 6 {
		t.Fatal("expiry and quota were not evaluated in same admission", err)
	}
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, at)
	if err != nil || view.LastGood.Software == nil || view.LastGood.Services != nil || view.LastGood.Processes != nil || view.LastGood.Volumes != nil || view.LastGood.Network != nil || view.LastGood.Events != nil {
		t.Fatal("quota recovery retained expired sections", err)
	}
}

func TestIndependentOperationalStoreReadAdmissionLeavesRevocationSlot(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	op := operationalStoreSnapshot(at, "services")
	raw := operationalStoreFrame(t, 1, at, &op)
	if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal(err)
	}
	db := operationalStoreDB(t, f.path)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal("fixture lock failed", err)
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	start := make(chan struct{})
	results := make(chan error, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			copied := *f.store
			_, err := copied.OperationalView(ctx, identity.Approval.DeviceID, at)
			results <- err
		}()
	}
	close(start)
	for range 31 {
		select {
		case err := <-results:
			if !errors.Is(err, enrollmentstore.ErrOperationalBusy) {
				t.Fatal("read admission did not bound outstanding database work", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("operational readers accumulated while database was busy")
		}
	}
	revokeResult := make(chan error, 1)
	began := time.Now()
	go func() {
		_, err := f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: f.nextRequest(), ExpectedRevision: identity.Revision, Now: at.Unix() + 1}, State: enrollmentstate.Revoked})
		revokeResult <- err
	}()
	if _, err = conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal("fixture unlock failed", err)
	}
	select {
	case err := <-revokeResult:
		if err != nil {
			t.Fatal("operator revocation failed behind admitted read", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revocation did not complete after read lock released")
	}
	select {
	case err := <-results:
		if err != nil {
			t.Fatal("single admitted reader failed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("admitted read did not complete")
	}
	wg.Wait()
	t.Logf("one admitted read, 31 immediate busy responses; operator revoke after lock release completed within %s", time.Since(began))
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, at.Add(time.Second))
	if err != nil || view.Status != "revoked" {
		t.Fatal("later read missed committed revoke", err)
	}
}

func TestIndependentOperationalStorePopulatedCapacityAndConcurrentProgress(t *testing.T) {
	f, first := operationalStoreFixture(t)
	ctx := context.Background()
	identities := []enrollmentstate.Snapshot{first}
	// Populate credentials first, then dense observations, so this measures the
	// supported final capacity rather than repeated fixture preparation overhead.
	for len(identities) < 25 {
		f.now.Add(60)
		identities = append(identities, operationalStoreActivate(t, f))
	}
	at := f.clock().Add(time.Second)
	op := operationalStoreDense(t, at, "software")
	raw := operationalStoreFrame(t, 1, at, &op)
	raw = append(raw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
	if _, err := lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal("exact wire-cap synthetic frame invalid", err)
	}
	for n, identity := range identities {
		unique := operationalStoreUniqueGeneration(op, n+1)
		uniqueRaw := operationalStoreFrame(t, 1, at, &unique)
		uniqueRaw = append(uniqueRaw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(uniqueRaw))...)
		if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, uniqueRaw, at); err != nil {
			t.Fatal("25-record dense population failed", err)
		}
	}
	operationalStoreAssertDistinctFrames(t, f.path, 25)
	if views, err := f.store.DeviceViews(ctx); err != nil || len(views) != 25 {
		t.Fatal("population count invalid", err)
	}
	other := independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
	third := independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
	nextAt := at.Add(time.Second)
	nextOp := operationalStoreDense(t, nextAt, "software")
	nextRaw := operationalStoreFrame(t, 2, nextAt, &nextOp)
	nextRaw = append(nextRaw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(nextRaw))...)
	before := make([][]byte, 3)
	for n := range 3 {
		before[n] = operationalStoreIdentityRows(t, f.path, identities[n].InvitationID)
	}
	perform := func(n int) error {
		var err error
		switch n {
		case 0:
			_, err = f.store.OperationalView(ctx, identities[0].Approval.DeviceID, nextAt)
		case 1:
			_, err = other.SaveObservation(ctx, identities[1].InvitationID, identities[1].Issuance.CertificateHash, nextRaw, nextAt)
		case 2:
			_, err = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identities[2].InvitationID, RequestID: independentEnrollmentID("request", 987654), ExpectedRevision: identities[2].Revision, Now: nextAt.Unix()}, State: enrollmentstate.Revoked})
		}
		return err
	}
	durations := make([]time.Duration, 3)
	operationErrors := make([]error, 3)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n := range 3 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			began := time.Now()
			operationErrors[n] = perform(n)
			durations[n] = time.Since(began)
		}(n)
	}
	close(start)
	wg.Wait()
	t.Logf("25 identities, synthetic frames exactly %d bytes; first-attempt read=%s (%v) observation=%s (%v) revoke=%s (%v)", len(raw), durations[0], operationErrors[0], durations[1], operationErrors[1], durations[2], operationErrors[2])
	for n, err := range operationErrors {
		if operationalStoreRaceBusyRetry(t, operationalStoreRaceInstrumented, err, f, identities[n], before[n]) {
			if err := perform(n); err != nil {
				t.Fatal("exact post-contention retry failed", err)
			}
		}
	}
	final, err := f.store.OperationalView(ctx, identities[1].Approval.DeviceID, nextAt)
	if err != nil || final.Sequence == nil || *final.Sequence != 2 || final.Snapshot == nil || final.Snapshot.GenerationID != nextOp.GenerationID {
		t.Fatal("observation/cache did not commit after concurrent work", err)
	}
	revoked, err := f.store.Get(ctx, identities[2].InvitationID)
	if err != nil || revoked.State != enrollmentstate.Revoked {
		t.Fatal("concurrent revocation did not persist", err)
	}

	if _, err := f.service.CreateInvitation(ctx, f.nextRequest(), "linux"); !errors.Is(err, enrollmentstate.ErrCapacity) {
		t.Fatal("revoked tombstone stopped consuming identity capacity", err)
	}
	t.Logf("25 identities, synthetic frames exactly %d bytes; concurrent read=%s observation=%s revoke=%s", len(raw), durations[0], durations[1], durations[2])
}

// Actual ingress timing uses a wall-clock-valid ephemeral issuer. No clock or
// certificate policy is bypassed to make the production handler accept it.
func operationalStoreWallClockFixture(t *testing.T, profile string) *independentServiceFixture {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("private enrollment SQLite adapter is Linux-only")
	}
	f := &independentServiceFixture{}
	f.now.Store(time.Now().UTC().Unix())
	origin := "https://manager.example"
	if profile == "http-test" {
		origin = "http://manager.example"
	}
	now := f.clock()
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral root generation failed")
	}
	rootSKI := sha256.Sum256(rootPub)
	root := &x509.Certificate{SerialNumber: big.NewInt(701), Subject: pkix.Name{CommonName: "Disposable service root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rootSKI[:20]}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if err != nil {
		t.Fatal("ephemeral root certificate failed")
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal("ephemeral root parse failed")
	}
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral issuer generation failed")
	}
	issuerSKI := sha256.Sum256(issuerPub)
	before := now.Add(-time.Hour)

	issuer := &x509.Certificate{SerialNumber: big.NewInt(702), Subject: pkix.Name{CommonName: "Disposable service intermediate"}, NotBefore: before, NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: issuerSKI[:20], AuthorityKeyId: root.SubjectKeyId}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, rootKey)
	if err != nil {
		t.Fatal("ephemeral intermediate certificate failed")
	}
	fingerprint := sha256.Sum256(issuerDER)
	f.issuer, err = enrollmentissuer.New(issuerDER, rootDER, issuerKey, hex.EncodeToString(fingerprint[:]), now)
	if err != nil {
		t.Fatal("ephemeral dedicated issuer rejected")
	}
	cfg := independentEnrollmentConfig()
	cfg.Binding.Origin, cfg.Binding.Profile = origin, profile
	cfg.Binding.CollectionProfile = operational.CollectionProfile
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	cfg.Binding.IssuerFingerprint = f.issuer.Fingerprint()
	f.path = filepath.Join(t.TempDir(), "private", "enrollment.sqlite")
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, issuerDER)
	f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
	if err != nil {
		t.Fatal("service fixture rejected")
	}
	_, f.key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral client generation failed")
	}
	f.keyDER, err = x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal("ephemeral client encoding failed")
	}
	f.csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.key)
	if err != nil {
		t.Fatal("ephemeral client CSR failed")
	}
	return f
}

func TestIndependentOperationalStoreActualIngressCrossHandleCapacityAndConcurrentProgress(t *testing.T) {
	operationalStoreActualIngressConcurrency(t, false)
}

// The production runtime shares one prepared Store/sql.DB between operator
// reads/revocation and ingress. Keep this distinct from cross-handle SQLite
// contention, whose fixed busy timeout can be reached under instrumentation.
func TestIndependentOperationalStoreActualIngressSameHandleCapacityAndConcurrentProgress(t *testing.T) {
	operationalStoreActualIngressConcurrency(t, true)
}

func operationalStoreActualIngressConcurrency(t *testing.T, shared bool) {
	topology := "cross-handle"
	if shared {
		topology = "same-handle"
	}
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := operationalStoreWallClockFixture(t, profile)
			ctx := context.Background()
			identities := make([]enrollmentstate.Snapshot, 0, 25)
			for len(identities) < 25 {
				// Fresh service instances prepare ordinary independent fixture identities
				// without manufacturing future certificate times to clear rate windows.
				var err error
				f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
				if err != nil {
					t.Fatal(err)
				}
				identities = append(identities, operationalStoreActivate(t, f))
			}
			at := time.Now().UTC()
			op := operationalStoreDense(t, at, "software")
			raw := operationalStoreFrame(t, 1, at, &op)
			raw = append(raw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
			for n, identity := range identities {
				unique := operationalStoreUniqueGeneration(op, n+1)
				uniqueRaw := operationalStoreFrame(t, 1, at, &unique)
				uniqueRaw = append(uniqueRaw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(uniqueRaw))...)
				if _, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, uniqueRaw, at); err != nil {
					t.Fatal("dense ingress fixture population failed", err)
				}
			}
			operationalStoreAssertDistinctFrames(t, f.path, 25)
			cert, err := f.store.CertificateForVerification(ctx, identities[1].InvitationID)
			if err != nil {
				t.Fatal(err)
			}
			pair := tls.Certificate{Certificate: [][]byte{cert.DER()}, PrivateKey: f.key}
			server := httptest.NewUnstartedServer(nil)
			t.Cleanup(server.Close)
			origin := "https://" + server.Listener.Addr().String()
			if profile == "http-test" {
				origin = "http://" + server.Listener.Addr().String()
			}
			ingress, err := enrollmenttransport.New(f.store, f.issuer.IssuerDER(), origin)
			if err != nil {
				t.Fatal("production ingress setup failed", err)
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
					t.Fatal("normal TLS listener configuration failed", err)
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
			other, third := f.store, f.store
			if !shared {
				other = independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
				third = independentEnrollmentStoreOpen(t, f.path, f.store.Config(), f.issuer.IssuerDER())
			}
			nextAt := time.Now().UTC()
			nextOp := operationalStoreDense(t, nextAt, "software")
			nextRaw := operationalStoreFrame(t, 2, nextAt, &nextOp)
			nextRaw = append(nextRaw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(nextRaw))...)
			var request *http.Request
			if profile == "tls" {
				request, err = http.NewRequestWithContext(ctx, http.MethodPost, origin+signedhttp.Path, bytes.NewReader(nextRaw))
				if err == nil {
					request.Header.Set("Content-Type", "application/json")
				}
			} else {
				request, err = signedhttp.NewSignedRequest(ctx, origin, pair, 2, nextAt, nextRaw)
			}
			if err != nil {
				t.Fatal("ordinary ingress request construction failed", err)
			}
			before := make([][]byte, 3)
			for n := range 3 {
				before[n] = operationalStoreIdentityRows(t, f.path, identities[n].InvitationID)
			}
			var receipt lanstore.Receipt
			perform := func(n int) error {
				var err error
				switch n {
				case 0:
					_, err = other.OperationalView(ctx, identities[0].Approval.DeviceID, nextAt)
				case 1:
					if request.GetBody == nil {
						return errors.New("exact request body cannot be replayed")
					}
					attempt := request.Clone(ctx)
					attempt.Body, err = request.GetBody()
					if err != nil {
						return err
					}
					var response *http.Response
					response, err = client.Do(attempt)
					if err == nil {
						defer response.Body.Close()
						var body []byte
						body, err = io.ReadAll(io.LimitReader(response.Body, 4096))
						if err == nil {
							if response.StatusCode == http.StatusOK {
								if json.Unmarshal(body, &receipt) != nil {
									err = errors.New("production receipt decode failed")
								}
							} else {
								var problem struct {
									Error struct {
										Code    string `json:"code"`
										Message string `json:"message"`
									} `json:"error"`
								}
								if response.StatusCode == http.StatusTooManyRequests && response.Header.Get("Retry-After") == "15" && json.Unmarshal(body, &problem) == nil && problem.Error.Code == "storage_busy" && problem.Error.Message == "Agent telemetry could not be accepted." {
									err = enrollmentstore.ErrBusy
								} else {
									err = fmt.Errorf("production ingress returned unexpected status %d", response.StatusCode)
								}
							}
						}
					}
				case 2:
					_, err = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identities[2].InvitationID, RequestID: independentEnrollmentID("request", 987655), ExpectedRevision: identities[2].Revision, Now: nextAt.Unix()}, State: enrollmentstate.Revoked})
				}
				return err
			}
			start := make(chan struct{})
			durations := make([]time.Duration, 3)
			operationErrors := make([]error, 3)
			var wg sync.WaitGroup
			for n := range 3 {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					<-start
					began := time.Now()
					operationErrors[n] = perform(n)
					durations[n] = time.Since(began)
				}(n)
			}
			close(start)
			wg.Wait()
			t.Logf("25 identities, actual %s %s ingress including transport, %d-byte synthetic frames; first-attempt read=%s (%v) ingress=%s (%v) revoke=%s (%v)", topology, profile, len(nextRaw), durations[0], operationErrors[0], durations[1], operationErrors[1], durations[2], operationErrors[2])
			for n, err := range operationErrors {
				if operationalStoreRaceBusyRetry(t, operationalStoreRaceInstrumented && !shared, err, f, identities[n], before[n]) {
					if err := perform(n); err != nil {
						t.Fatal("exact post-contention ingress/runtime retry failed", err)
					}
				}
			}

			if receipt.AgentID != identities[1].Approval.DeviceID || receipt.Sequence != 2 || receipt.Duplicate || !receipt.CollectedAt.Equal(nextAt) {
				t.Fatal("actual ingress receipt did not bind committed observation")
			}
			view, err := f.store.OperationalView(ctx, identities[1].Approval.DeviceID, time.Now().UTC())
			if err != nil || view.Sequence == nil || *view.Sequence != 2 || view.Snapshot == nil || view.Snapshot.GenerationID != nextOp.GenerationID {
				t.Fatal("actual ingress cache and raw frame were not committed together", err)
			}
			revoked, err := f.store.Get(ctx, identities[2].InvitationID)
			if err != nil || revoked.State != enrollmentstate.Revoked {
				t.Fatal("concurrent operator revoke did not persist", err)
			}
		})
	}
}

// Distinct real devices do not share an observation generation. This prevents
// transaction-local exact-frame parse reuse from collapsing the capacity fixture.
func operationalStoreUniqueGeneration(s operational.Snapshot, n int) operational.Snapshot {
	s.GenerationID = fmt.Sprintf("sample_%032x", n)
	for _, m := range []*operational.SectionMeta{&s.Sections.Volumes.Meta, &s.Sections.Network.Meta, &s.Sections.Services.Meta, &s.Sections.Processes.Meta, &s.Sections.Software.Meta, &s.Sections.Events.Meta} {
		m.GenerationID = s.GenerationID
	}
	return s
}

func operationalStoreAssertDistinctFrames(t *testing.T, path string, want int) {
	t.Helper()
	db := operationalStoreDB(t, path)
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(DISTINCT json_extract(body,'$.replay.payloadHash')) FROM enrollment_credentials").Scan(&count); err != nil || count != want {
		t.Fatal("capacity fixture did not retain distinct per-device raw frames", err)
	}
}

func TestIndependentOperationalStoreInitialBusyPreservesAdmissionCacheAndRevocation(t *testing.T) {
	f, identity := operationalStoreFixture(t)
	ctx := context.Background()
	at := f.clock().Add(time.Second)
	first := operationalStoreSnapshot(at, "services")
	firstRaw := operationalStoreFrame(t, 1, at, &first)
	firstReceipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, firstRaw, at)
	if err != nil {
		t.Fatal(err)
	}
	nextAt := at.Add(time.Second)
	next := operationalStoreSnapshot(nextAt, "software")
	nextRaw := operationalStoreFrame(t, 2, nextAt, &next)
	revoke := enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: identity.InvitationID, RequestID: f.nextRequest(), ExpectedRevision: identity.Revision, Now: nextAt.Add(4 * time.Second).Unix()}, State: enrollmentstate.Revoked}
	admissionBefore := operationalStoreIdentityRows(t, f.path, identity.InvitationID)
	var admissionBusy error
	for _, operation := range []string{"read", "admission", "revocation"} {
		t.Run(operation, func(t *testing.T) {
			before := operationalStoreRows(t, f.path)
			db := operationalStoreDB(t, f.path)
			connection, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if _, err = connection.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
				t.Fatal("fixture lock failed", err)
			}
			defer connection.ExecContext(ctx, "ROLLBACK")
			switch operation {
			case "read":
				var out enrollmentstore.OperationalView
				out, err = f.store.OperationalView(ctx, identity.Approval.DeviceID, nextAt)
				if out.Snapshot != nil || out.ReceivedAt != nil || out.Sequence != nil {
					t.Fatal("busy read returned authoritative operational data")
				}
			case "admission":
				var out lanstore.Receipt
				out, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, nextRaw, nextAt)
				admissionBusy = err
				if out != (lanstore.Receipt{}) {
					t.Fatal("busy admission returned a receipt")
				}
			case "revocation":
				var out enrollmentstate.Snapshot
				out, err = f.store.Terminate(ctx, revoke)
				if out != (enrollmentstate.Snapshot{}) {
					t.Fatal("busy revocation returned a lifecycle transition")
				}
			}
			if !errors.Is(err, enrollmentstore.ErrBusy) || errors.Is(err, enrollmentstore.ErrStorage) {
				t.Fatal("initial contention was not the exact typed busy category", err)
			}
			if _, err = connection.ExecContext(ctx, "ROLLBACK"); err != nil {
				t.Fatal("fixture unlock failed", err)
			}
			if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
				t.Fatal("busy initial BEGIN changed authority, exact frame, receipt, or retained cache")
			}
			view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, nextAt)
			if err != nil || view.Status != "fresh" || view.Sequence == nil || *view.Sequence != firstReceipt.Sequence || view.ReceivedAt == nil || !view.ReceivedAt.Equal(firstReceipt.ReceivedAt) || view.LastGood.Services == nil || view.LastGood.Services.Meta.GenerationID != first.GenerationID || view.LastGood.Software != nil {
				t.Fatal("state did not survive busy/release", err)
			}
		})
	}
	if operationalStoreRaceInstrumented && !operationalStoreRaceBusyRetry(t, true, admissionBusy, f, identity, admissionBefore) {
		t.Fatal("real busy did not exercise race-only invariance branch")
	}
	receipt, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, nextRaw, nextAt)
	if err != nil || receipt.Duplicate || receipt.Sequence != 2 || !receipt.ReceivedAt.Equal(nextAt) {
		t.Fatal("exact authorized admission did not succeed after contention", err)
	}
	duplicate, err := f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, nextRaw, nextAt.Add(time.Second))
	if err != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("post-contention duplicate refreshed receipt", err)
	}
	view, err := f.store.OperationalView(ctx, identity.Approval.DeviceID, nextAt.Add(2*time.Second))
	if err != nil || view.Snapshot == nil || view.Snapshot.GenerationID != next.GenerationID || view.LastGood.Services == nil || view.LastGood.Software == nil || view.LastGood.Services.Meta.GenerationID != first.GenerationID || view.LastGood.Software.Meta.GenerationID != next.GenerationID {
		t.Fatal("post-contention commit lost mixed cache provenance", err)
	}
	terminated, err := f.store.Terminate(ctx, revoke)
	if err != nil || terminated.State != enrollmentstate.Revoked {
		t.Fatal("exact authorized revocation did not succeed after contention", err)
	}
	before := operationalStoreRows(t, f.path)
	if _, err = f.store.SaveObservation(ctx, identity.InvitationID, identity.Issuance.CertificateHash, nextRaw, nextAt.Add(5*time.Second)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("retry semantics revived revoked identity", err)
	}
	if !bytes.Equal(before, operationalStoreRows(t, f.path)) {
		t.Fatal("revoked post-contention retry changed durable rows")
	}
}

// Native capacity and shared-Store runtime assertions remain strict. Only the
// separately instrumented cross-handle topology may exercise a proved initial
// BEGIN refusal, with identity-local state invariance before the exact retry.
func operationalStoreRaceBusyRetry(t *testing.T, allowed bool, err error, f *independentServiceFixture, identity enrollmentstate.Snapshot, before []byte) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if !allowed || !errors.Is(err, enrollmentstore.ErrBusy) || errors.Is(err, enrollmentstore.ErrStorage) {
		t.Fatal("first-attempt capacity operation failed outside typed race/cross-handle contract", err)
	}
	if !bytes.Equal(before, operationalStoreIdentityRows(t, f.path, identity.InvitationID)) {
		t.Fatal("busy operation changed exact receipt/frame/retained cache")
	}
	after, readErr := f.store.Get(context.Background(), identity.InvitationID)
	if readErr != nil || after != identity {
		t.Fatal("busy operation changed lifecycle authority", readErr)
	}
	t.Log("race-only cross-handle initial busy preserved identity/frame/receipt/cache; exact post-contention retry follows")
	return true
}

func operationalStoreIdentityRows(t *testing.T, path, id string) []byte {
	t.Helper()
	db := operationalStoreDB(t, path)
	defer db.Close()
	var out bytes.Buffer
	for _, table := range []string{"enrollment_credentials", "enrollment_operational"} {
		var raw []byte
		if err := db.QueryRow("SELECT body FROM "+table+" WHERE invitation_id=?", id).Scan(&raw); err != nil {
			t.Fatal("identity-local fixture read failed", err)
		}
		out.Write(raw)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
