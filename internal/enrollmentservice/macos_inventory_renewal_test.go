package enrollmentservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func activatedMacInventoryRenewalFixture(t *testing.T) (*fixture, enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t, "tls", true)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	f.config.Platform = "darwin"
	f.path = filepath.Join(t.TempDir(), "private", "mac-inventory-renewal.db")
	f.restart(t)
	ctx := context.Background()
	pending, key := claimForPlatform(t, f, "darwin")
	if _, err := f.service.Approve(ctx, pending.InvitationID, id("request", 4), pending.Claim.KeyFingerprint, pending.Revision); err != nil {
		t.Fatal(err)
	}
	c, body := status(t, f, pending.InvitationID, pending.Claim.ClaimID, "status", 5, key)
	if _, err := f.service.Status(ctx, c.Context.Challenge, body); err != nil {
		t.Fatal(err)
	}
	cert, err := f.store.CertificateForVerification(ctx, pending.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	c = challenge(t, f, pending.InvitationID, pending.Claim.ClaimID, "activation")
	message, err := enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), id("request", 7), cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": id("request", 7), "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	active, err := f.service.Activate(ctx, c.Context.Challenge, body)
	if err != nil {
		t.Fatal(err)
	}
	return f, active, key
}

func TestMacOSInventoryRenewalPreservesOriginalBindingReceiptAndLifetime(t *testing.T) {
	f, active, key := activatedMacInventoryRenewalFixture(t)
	ctx := context.Background()
	anchor, e := f.store.CertificateForVerification(ctx, active.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	f.now = time.Unix(active.Intent.NotAfter, 0).UTC().Add(-time.Hour)
	captured := f.now
	origin := f.config.RenewalAgentOrigin
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.macos-inventory.v1\nmacos-read-inventory-v1\ntls\n" + origin + "\n" + anchor.CertificateHash() + "\n" + active.Approval.DeviceID))
	control := macosinventorywire.Control{SchemaVersion: macosinventorywire.ControlVersion, Binding: macosinventorywire.Binding{Platform: "darwin", Profile: macosinventorywire.Profile, DeviceID: active.Approval.DeviceID, SenderBinding: hex.EncodeToString(sum[:])}, GrantID: strings.Repeat("d", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: captured}
	raw, _ := macosinventorywire.EncodeControl(control)
	ingress := enrollmentstore.WithMacOSInventoryIngressOrigin(ctx, origin)
	if _, e = f.store.ApplyMacOSInventoryControl(ingress, active.InvitationID, anchor.CertificateHash(), raw, f.now); e != nil {
		t.Fatal("enable", e)
	}
	generation, _ := macosinventorywire.GenerationID(control.Binding, control.GrantID, 1, 1)
	snapshot := macosinventory.Empty(macosinventory.Request{Consent: macosinventory.Consent{GrantID: control.GrantID}, GenerationID: generation, CollectedAt: captured}, macosinventory.ErrUnavailable.Error())
	report, e := macosinventorywire.BuildReport(control, 1, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = macosinventorywire.EncodeReport(report)
	if e != nil {
		t.Fatal(e)
	}
	original, e := f.store.ApplyMacOSInventoryReport(ingress, active.InvitationID, anchor.CertificateHash(), raw, f.now)
	if e != nil {
		t.Fatal("report", e)
	}
	c, body := renewalProof(t, f, active, key, anchor.CertificateHash(), enrollmentcrypto.PurposeRenewalIssue, 700)
	issued, e := f.service.Renew(ctx, c.Context.Challenge, body)
	if e != nil || issued.Candidate == nil {
		t.Fatal("renewal issue", e)
	}
	c, body = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 701)
	renewed, e := f.service.ActivateRenewal(ctx, c.Context.Challenge, body)
	if e != nil {
		t.Fatal("renewal activation", e)
	}
	f.now = time.Unix(active.Intent.NotAfter+1, 0).UTC()
	f.restart(t)
	current := enrollmentstore.WithAuthenticatedCertificate(ingress, renewed.Current.CertificateHash)
	retry, e := f.store.ApplyMacOSInventoryReport(current, active.InvitationID, anchor.CertificateHash(), raw, f.now)
	if e != nil || !bytes.Equal(original, retry) {
		t.Fatal("original receipt/binding changed", e)
	}
	if _, e = f.store.ApplyMacOSInventoryReport(enrollmentstore.WithAuthenticatedCertificate(ingress, anchor.CertificateHash()), active.InvitationID, anchor.CertificateHash(), raw, f.now); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("retired transport admitted", e)
	}
	pageCtx := enrollmentstore.WithMacOSInventorySession(ctx, "fixture-session", f.now.Add(48*time.Hour), func() bool { return true })
	page, e := f.service.MacOSInventoryPage(pageCtx, active.Approval.DeviceID, enrollmentstore.MacOSInventoryQuery{Section: "summary", Limit: 100}, f.now)
	if e != nil || page.Status != "stale" || page.CollectedAt == nil || !page.CollectedAt.Equal(captured) || page.ExpiresAt == nil || !page.ExpiresAt.Equal(captured.Add(24*time.Hour)) || page.GenerationID != generation {
		t.Fatal("renewal refreshed capture or failed read", e)
	}
	f.now = captured.Add(24 * time.Hour)
	if _, e = f.store.ApplyMacOSInventoryReport(current, active.InvitationID, anchor.CertificateHash(), raw, f.now); !errors.Is(e, macosinventorywire.ErrExpired) {
		t.Fatal("renewal extended source retention", e)
	}
	if _, e = f.service.Terminate(ctx, active.InvitationID, id("request", 702), active.Revision, enrollmentstate.Revoked); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.MacOSInventoryPage(pageCtx, active.Approval.DeviceID, enrollmentstore.MacOSInventoryQuery{Section: "summary", Limit: 100}, f.now); !errors.Is(e, enrollmentstate.ErrState) {
		t.Fatal("revoked renewed private read", e)
	}
}
func TestMacOSInventoryMaintenanceCancelsWithoutNativeOrListener(t *testing.T) {
	f, _, _ := activatedMacInventoryRenewalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := f.service.RunMacOSInventoryMaintenance(ctx, func() { t.Error("canceled loop warned") }); e != nil {
		t.Fatal(e)
	}
}

func TestMacOSInventoryHistoricalContactProjectionContainsNoRows(t *testing.T) {
	f, active, _ := activatedMacInventoryRenewalFixture(t)
	ctx := context.Background()
	at := f.now
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.macos-inventory.v1\nmacos-read-inventory-v1\ntls\n" + f.config.RenewalAgentOrigin + "\n" + active.Issuance.CertificateHash + "\n" + active.Approval.DeviceID))
	control := macosinventorywire.Control{SchemaVersion: macosinventorywire.ControlVersion, Binding: macosinventorywire.Binding{Platform: "darwin", Profile: macosinventorywire.Profile, DeviceID: active.Approval.DeviceID, SenderBinding: hex.EncodeToString(sum[:])}, GrantID: strings.Repeat("e", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: at}
	ingress := enrollmentstore.WithMacOSInventoryIngressOrigin(ctx, f.config.RenewalAgentOrigin)
	body, _ := macosinventorywire.EncodeControl(control)
	if _, e := f.store.ApplyMacOSInventoryControl(ingress, active.InvitationID, active.Issuance.CertificateHash, body, at); e != nil {
		t.Fatal(e)
	}
	generation, _ := macosinventorywire.GenerationID(control.Binding, control.GrantID, 1, 1)
	snapshot := macosinventory.Empty(macosinventory.Request{Consent: macosinventory.Consent{GrantID: control.GrantID}, GenerationID: generation, CollectedAt: at}, macosinventory.ErrUnavailable.Error())
	snapshot.Receipts = macosinventory.Receipts{Status: macosinventory.Status{Source: macosinventory.ReceiptSource, Quality: "observed"}, Identifiers: []string{"org.example.private-receipt"}}
	report, e := macosinventorywire.BuildReport(control, 1, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	body, _ = macosinventorywire.EncodeReport(report)
	if _, e = f.store.ApplyMacOSInventoryReport(ingress, active.InvitationID, active.Issuance.CertificateHash, body, at); e != nil {
		t.Fatal(e)
	}
	f.now = at.Add(time.Minute)
	rows, e := f.service.Devices(ctx, f.now)
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	d := rows[0]
	encoded, _ := json.Marshal(d)
	if d.OS != "macOS inventory" || !d.LastSeen.Equal(at) || d.Status != "unknown" || d.CPU.Value != nil || d.Memory.Value != nil || d.Disk.Value != nil || len(d.Evidence) != 0 || bytes.Contains(encoded, []byte("private-receipt")) {
		t.Fatal("contact projection widened authority")
	}
	if !bytes.Contains(encoded, []byte("accepted receipt")) {
		t.Fatal("original receipt contact missing")
	}
	if _, e = f.store.ApplyMacOSInventoryReport(ingress, active.InvitationID, active.Issuance.CertificateHash, body, f.now); e != nil {
		t.Fatal(e)
	}
	after, e := f.service.Devices(ctx, f.now)
	if e != nil || !after[0].LastSeen.Equal(at) {
		t.Fatal("retry refreshed contact", e)
	}
}
