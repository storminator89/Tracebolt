package enrollmentservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistorycache"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorywire"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func activatedHistoryRenewalFixture(t *testing.T) (*fixture, enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t, "tls", true)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.path = filepath.Join(t.TempDir(), "private", "history-renewal.db")
	f.restart(t)
	ctx := context.Background()
	pending, key := claimForPlatform(t, f, "windows")
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

func TestWindowsHistoryRenewalPreservesReceiptCacheAndSelectedClaim(t *testing.T) {
	f, active, key := activatedHistoryRenewalFixture(t)
	ctx := context.Background()
	device, anchor := active.Approval.DeviceID, active.Issuance.CertificateHash
	f.now = time.Unix(active.Intent.NotAfter, 0).UTC().Add(-10 * time.Minute)
	if err := f.service.InitializeWindowsHistory(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.service.CloseWindowsHistory)
	consent := windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, HistoryAcknowledged: true, ContentAcknowledged: true}
	capability, err := windowshistorywire.CapabilityFor(consent, windowshistoryrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: "tls", DeviceID: device, CertificateHash: anchor}, 1, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReportWindowsHistoryCapability(ctx, device, anchor, capability, f.now); err != nil {
		t.Fatal(err)
	}
	owner := windowshistorycache.Owner{ID: "history-renewal-operator", ExpiresAt: f.now.Add(time.Hour), Lifetime: ctx, Active: func() bool { return true }}
	search := windowseventhistory.Search{Channel: "Application", Start: f.now.Add(-time.Hour), End: f.now}
	description, err := f.service.CreateWindowsHistorySearch(ctx, device, owner, 0, search, f.now)
	if err != nil {
		t.Fatal(err)
	}
	claim, _ := windowshistorywire.ClaimFor(description, capability.PolicyDigest)
	if _, err = f.service.ClaimWindowsHistoryRequest(ctx, device, anchor, claim, f.now); err != nil {
		t.Fatal(err)
	}
	event := windowseventhistory.Event{Channel: "Application", RecordID: 1, EventID: 42, Level: 2, Provider: "Synthetic history renewal", Timestamp: f.now.Add(-time.Minute)}
	result := windowshistorywire.Result{Claim: claim, Report: windowseventhistory.Report{Source: windowseventhistory.Source, Warning: windowseventhistory.PrivacyWarning, Quality: "observed", CollectedAt: f.now, Complete: true, Search: &search, Events: []windowseventhistory.Result{{Event: event, Quality: "observed", Complete: true}}}}
	receipt, err := f.service.AcceptWindowsHistoryResult(ctx, device, anchor, result, f.now)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.service.WindowsHistoryQuery(ctx, device, owner, description.Identity, f.now)
	if err != nil || before.ExpiresAt.Unix() != active.Intent.NotAfter {
		t.Fatal("original cache deadline", err)
	}
	f.now = f.now.Add(time.Second)
	challenge, proof := renewalProof(t, f, active, key, anchor, enrollmentcrypto.PurposeRenewalIssue, 400)
	issued, err := f.service.Renew(ctx, challenge.Context.Challenge, proof)
	if err != nil || issued.Candidate == nil {
		t.Fatal("issue", err)
	}
	challenge, proof = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 401)
	activated, err := f.service.ActivateRenewal(ctx, challenge.Context.Challenge, proof)
	if err != nil {
		t.Fatal("activate", err)
	}
	if err = f.service.MaintainWindowsHistory(ctx, f.now); err != nil {
		t.Fatal("renewal maintenance", err)
	}
	after, err := f.service.WindowsHistoryQuery(ctx, device, owner, description.Identity, f.now)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("renewal changed retained result/deadline", err)
	}
	transport := enrollmentstore.WithAuthenticatedCertificate(ctx, activated.Current.CertificateHash)
	for _, wrong := range []string{"device", "anchor", "grant"} {
		badDevice, badAnchor, badResult := device, anchor, result
		switch wrong {
		case "device":
			badDevice = id("agent", 999)
		case "anchor":
			badAnchor = strings.Repeat("e", 64)
		case "grant":
			badResult.Claim.GrantID = strings.Repeat("d", 32)
		}
		if _, _, err = f.store.AcceptWindowsHistoryResult(transport, badDevice, badAnchor, badResult, f.now); err == nil {
			t.Fatal("wrong binding accepted", wrong)
		}
	}
	if retry, first, e := f.store.AcceptWindowsHistoryResult(transport, device, anchor, result, f.now); e != nil || first || retry != receipt {
		t.Fatal("exact receipt retry", e)
	}
	messages, err := f.service.CreateWindowsHistoryMessages(ctx, device, owner, 1, receipt, []windowshistoryrequest.Selection{{Channel: "Application", RecordID: "1"}}, f.now)
	if err != nil || messages.CertificateHash != anchor || messages.ExpiresAt != description.ExpiresAt {
		t.Fatal("followup anchor/expiry", err)
	}
	messageClaim, _ := windowshistorywire.ClaimFor(messages, capability.PolicyDigest)
	retired := enrollmentstore.WithAuthenticatedCertificate(ctx, anchor)
	if _, err = f.service.ClaimWindowsHistoryRequest(retired, device, anchor, messageClaim, f.now); err == nil {
		t.Fatal("retired transport claimed")
	}
	if _, err = f.service.ClaimWindowsHistoryRequest(transport, device, anchor, messageClaim, f.now); err != nil {
		t.Fatal("current transport claim", err)
	}
	if _, err = f.service.Terminate(ctx, active.InvitationID, id("request", 402), active.Revision, enrollmentstate.Revoked); err != nil {
		t.Fatal(err)
	}
	if err = f.service.MaintainWindowsHistory(ctx, f.now); err != nil {
		t.Fatal("revocation maintenance", err)
	}
	if _, err = f.service.WindowsHistoryQuery(ctx, device, owner, messages.Identity, f.now); err == nil {
		t.Fatal("revoked history remained live")
	}
}
