package enrollmentservice

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
)

func activatedEventRenewalFixture(t *testing.T) (*fixture, enrollmentstate.Snapshot, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t, "tls", true)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.path = filepath.Join(t.TempDir(), "private", "event-renewal.db")
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

func renewalEventFrame(t *testing.T, at time.Time) []byte {
	t.Helper()
	value := 42.0
	metric := model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Synthetic measured fixture", CollectedAt: at}
	report := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Windows fixture", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Fixture", Scope: "Explicit hostname scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "fixture-windows"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Fixture", Scope: "Bounded process scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 12, Name: "fixture.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Fixture", Scope: "Denied service scope", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Fixture", Scope: "Partial software scope", Quality: "limited", Rows: []windowsinventory.Software{{Name: "Fixture app", Version: "1", Publisher: "Fixture", RegistryView: "64"}}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Fixture", Scope: "Explicit interface scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 1, Name: "Fixture", Address: "192.0.2.8", PrefixLength: 24}}}}
	inventory, device, err := windowsmanaged.FromReport(report, id("sample", 1))
	if err != nil {
		t.Fatal(err)
	}
	frame := windowsDashboardFrame("windows", 1, at)
	frame.SchemaVersion = lanstore.FrameWindowsEventsVersion
	frame.Observation.Observation = device
	frame.WindowsInventory = &inventory
	frame.WindowsEvents = &windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("c", 32), GenerationID: id("sample", 1), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: "1", EventID: 14, Level: 2, Provider: "Synthetic fixture", Timestamp: at}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	return marshalWindowsDashboardFrame(t, frame, at)
}

func TestRenewalWindowsEventMaintenancePreservesRetainedAuthority(t *testing.T) {
	for _, boundary := range []string{"expiry", "grant", "revocation", "restart"} {
		t.Run(boundary, func(t *testing.T) {
			f, active, key := activatedEventRenewalFixture(t)
			ctx := context.Background()
			device, anchor := active.Approval.DeviceID, active.Issuance.CertificateHash
			// The original cache deadline is clipped by the old leaf. Renewal may
			// keep the identity live, but must never extend this retained result.
			f.now = time.Unix(active.Intent.NotAfter, 0).UTC().Add(-10 * time.Minute)
			if err := f.service.InitializeWindowsEventContent(ctx); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.service.CloseWindowsEventContent() })
			consent := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
			capability, err := windowseventwire.CapabilityFor(consent, windowseventrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: "tls", DeviceID: device, CertificateHash: anchor}, 1, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.ReportWindowsEventCapability(ctx, device, anchor, capability, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.SaveObservation(ctx, active.InvitationID, anchor, renewalEventFrame(t, f.now), f.now); err != nil {
				t.Fatal(err)
			}
			status, err := f.store.WindowsEventContentStatus(ctx, device, f.now)
			if err != nil || status.Headers == nil {
				t.Fatal("event headers", err)
			}
			owner := windowseventcache.Owner{ID: "fixture-operator", ExpiresAt: f.now.Add(time.Hour), Lifetime: ctx, Active: func() bool { return true }}
			description, err := f.service.CreateWindowsEventRequest(ctx, device, owner, 0, status.Headers.GenerationID, status.Headers.SnapshotDigest, []windowseventrequest.Selection{{Channel: "Application", RecordID: "1"}}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := windowseventwire.ClaimFor(description, capability.PolicyDigest)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.ClaimWindowsEventRequest(ctx, device, anchor, claim, f.now); err != nil {
				t.Fatal(err)
			}
			result := windowseventwire.Result{Claim: claim, Report: windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: "observed", CollectedAt: f.now, Complete: true, Events: []windowseventcontent.Result{{Event: description.Query.Events[0], Message: "synthetic retained fixture", Quality: "observed", Complete: true}}}}
			receipt, err := f.service.AcceptWindowsEventResult(ctx, device, anchor, result, f.now)
			if err != nil {
				t.Fatal(err)
			}
			before, err := f.service.WindowsEventContentQuery(ctx, device, owner, description.Identity, f.now)
			if err != nil || before.ExpiresAt.Unix() != active.Intent.NotAfter {
				t.Fatal("original retained deadline", err)
			}
			f.now = f.now.Add(time.Second)
			challenge, proof := renewalProof(t, f, active, key, anchor, enrollmentcrypto.PurposeRenewalIssue, 300)
			issued, err := f.service.Renew(ctx, challenge.Context.Challenge, proof)
			if err != nil || issued.Candidate == nil {
				t.Fatal("issue", err)
			}
			challenge, proof = renewalProof(t, f, active, key, issued.Candidate.CertificateHash, enrollmentcrypto.PurposeRenewalActivate, 301)
			activated, err := f.service.ActivateRenewal(ctx, challenge.Context.Challenge, proof)
			if err != nil {
				t.Fatal("activate", err)
			}
			if err = f.service.MaintainWindowsEventContent(ctx, f.now); err != nil {
				t.Fatal("renewal broke retained event maintenance", err)
			}
			after, err := f.service.WindowsEventContentQuery(ctx, device, owner, description.Identity, f.now)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("renewal changed retained bytes, receipt or original deadline", err)
			}
			current := activated.Current.CertificateHash
			transport := enrollmentstore.WithAuthenticatedCertificate(ctx, current)
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
				if _, _, err = f.store.AcceptWindowsEventResult(transport, badDevice, badAnchor, badResult, f.now); err == nil {
					t.Fatal("renewal admitted wrong binding", wrong)
				}
			}
			if retry, first, err := f.store.AcceptWindowsEventResult(transport, device, anchor, result, f.now); err != nil || first || retry != receipt {
				t.Fatal("exact accepted retry lost original receipt", err)
			}
			switch boundary {
			case "expiry":
				f.now = before.ExpiresAt
			case "grant":
				capability.Sequence++
				capability.CollectedAt = f.now
				capability.Consent.GrantID = strings.Repeat("d", 32)
				capability.PolicyDigest, _ = windowseventwire.PolicyDigest(capability.Consent)
				if _, err = f.service.ReportWindowsEventCapability(transport, device, anchor, capability, f.now); err != nil {
					t.Fatal(err)
				}
			case "revocation":
				if _, err = f.service.Terminate(ctx, active.InvitationID, id("request", 302), active.Revision, enrollmentstate.Revoked); err != nil {
					t.Fatal(err)
				}
			case "restart":
				f.service.CloseWindowsEventContent()
				f.restart(t)
				if err = f.service.InitializeWindowsEventContent(ctx); err != nil {
					t.Fatal("renewed authority blocked restart", err)
				}
				status, err = f.store.WindowsEventContentStatus(ctx, device, f.now)
				if err != nil || status.Request == nil || status.Request.Receipt == nil || *status.Request.Receipt != receipt || status.ExpectedFloor != "1" {
					t.Fatal("restart changed accepted metadata or floor", err)
				}
			}
			if err = f.service.MaintainWindowsEventContent(ctx, f.now); err != nil {
				t.Fatal("terminal maintenance", err)
			}
			if _, err = f.service.WindowsEventContentQuery(ctx, device, owner, description.Identity, f.now); err == nil {
				t.Fatal("retained content outlived original authority", boundary)
			}
		})
	}
}
