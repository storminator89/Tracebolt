package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
)

func windowsServiceReviewRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_windows_action_records WHERE invitation_id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsServiceReviewExpectedBindingChecksAllFieldsBeforeObservationOrPreview(t *testing.T) {
	s, key, b, at, id, _ := windowsActionFixture(t)
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	actor, job := "operator_"+strings.Repeat("2", 32), "action_"+strings.Repeat("3", 32)
	for _, field := range []string{"manager", "key", "endpoint", "incarnation", "installation", "grant", "target", "target digest"} {
		t.Run(field, func(t *testing.T) {
			replacement := b
			switch field {
			case "manager":
				replacement.ManagerID = "manager_" + strings.Repeat("f", 32)
			case "key":
				replacement.KeyID = windowsaction.Digest([]byte("different key"))
			case "endpoint":
				replacement.EndpointID = "agent_" + strings.Repeat("f", 32)
			case "incarnation":
				replacement.IncarnationDigest = windowsaction.Digest([]byte("different incarnation"))
			case "installation":
				replacement.InstallationID = "broker_" + strings.Repeat("f", 32)
			case "grant":
				replacement.GrantDigest = windowsaction.Digest([]byte("different grant"))
			case "target":
				replacement.Target = strings.ToLower(b.Target)
			case "target digest":
				replacement.TargetDigest = windowsaction.Digest([]byte("different target config"))
			}
			digest := windowsaction.ServiceReviewBindingDigest(replacement)
			if digest == "" || digest == windowsaction.ServiceReviewBindingDigest(b) {
				t.Fatal("binding field absent from digest")
			}
			before := windowsServiceReviewRaw(t, s, id)
			if _, _, err := s.WindowsServiceActionViewExpected(context.Background(), pub, b.EndpointID, digest, at.Add(time.Second)); !errors.Is(err, windowsactionjob.ErrConflict) {
				t.Fatal("mismatched view", err)
			}
			if _, err := s.PreviewWindowsServiceActionExpected(context.Background(), pub, b.EndpointID, job, actor, b.Target, windowsaction.Restart, digest, at.Add(time.Second)); !errors.Is(err, windowsactionjob.ErrConflict) {
				t.Fatal("mismatched preview", err)
			}
			if !bytes.Equal(before, windowsServiceReviewRaw(t, s, id)) {
				t.Fatal("mismatch advanced floor or created preview")
			}
		})
	}
	for _, bad := range []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if _, _, err := s.WindowsServiceActionViewExpected(context.Background(), pub, b.EndpointID, bad, at); !errors.Is(err, windowsaction.ErrInvalid) {
			t.Fatal("invalid view digest", err)
		}
		if _, err := s.PreviewWindowsServiceActionExpected(context.Background(), pub, b.EndpointID, job, actor, b.Target, windowsaction.Restart, bad, at); !errors.Is(err, windowsaction.ErrInvalid) {
			t.Fatal("invalid preview digest", err)
		}
	}
}

func TestWindowsServiceReviewExpectedViewOnlyAdvancesClockAndPreviewRequiresBroker(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	expected := windowsaction.ServiceReviewBindingDigest(b)
	now := at.Add(time.Second)
	record, observed, err := s.WindowsServiceActionViewExpected(context.Background(), pub, b.EndpointID, expected, now)
	if err != nil || !record.ClockFloor.Equal(now) || !observed.Equal(now) || record.Preview != nil || len(record.Jobs) != 0 || record.Sequence != 0 || record.Capabilities != nil {
		t.Fatal("view created work or omitted durable clock", err)
	}
	job, actor := "action_"+strings.Repeat("3", 32), "operator_"+strings.Repeat("2", 32)
	if _, err = s.PreviewWindowsServiceActionExpected(context.Background(), pub, b.EndpointID, job, actor, b.Target, windowsaction.Restart, expected, now); !errors.Is(err, windowsaction.ErrUnavailable) {
		t.Fatal("missing broker promoted", err)
	}
	if err = s.ReportWindowsServiceActions(context.Background(), pub, id, hash, windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: now.Unix(), Enabled: true}, now); err != nil {
		t.Fatal(err)
	}
	record, err = s.PreviewWindowsServiceActionExpected(context.Background(), pub, b.EndpointID, job, actor, b.Target, windowsaction.Restart, expected, now)
	if err != nil || record.Preview == nil || len(record.Jobs) != 0 || record.Sequence != 0 {
		t.Fatal("manual preview", err)
	}
	if record.Preview.Binding != b || record.Preview.Operation != windowsaction.Restart || record.Preview.ActorID != actor {
		t.Fatal("manual preview binding changed")
	}
	// The unchanged v1 approval still needs this exact independently reviewed ID/digest.
	if _, err = s.ApproveWindowsServiceAction(context.Background(), pub, b.EndpointID, record.Preview.ID, windowsaction.Digest([]byte("wrong")), actor, now, signWindowsAction(key)); err == nil {
		t.Fatal("binding digest became approval authority")
	}
}

func TestWindowsServiceReviewExpectedFinalPreviewAndAuthorityExpiry(t *testing.T) {
	for _, expiry := range []string{"preview", "authority"} {
		t.Run(expiry, func(t *testing.T) {
			s, key, b, at, id, hash := windowsActionFixture(t)
			pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
			if err := s.ReportWindowsServiceActions(context.Background(), pub, id, hash, windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}, at); err != nil {
				t.Fatal(err)
			}
			end := at.Add(time.Minute)
			if expiry == "authority" {
				if err := s.transact(context.Background(), func(tx *transaction) error {
					snap, err := tx.engine.Get(id)
					end = time.Unix(tx.currentCredentialNotAfter(snap), 0).UTC()
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			ctx := WithOverviewClock(context.Background(), func() time.Time {
				calls++
				if calls == 1 {
					return at
				}
				return end
			})
			record, err := s.PreviewWindowsServiceActionExpected(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), "operator_"+strings.Repeat("2", 32), b.Target, windowsaction.Restart, windowsaction.ServiceReviewBindingDigest(b), at)
			if err == nil || record.Preview != nil || len(record.Jobs) != 0 {
				t.Fatal("expired preview or authority escaped", err)
			}
			var saved windowsactionjob.Record
			if err = json.Unmarshal(windowsServiceReviewRaw(t, s, id), &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Preview != nil || len(saved.Jobs) != 0 || saved.RejectedClockFloor == nil || !saved.RejectedClockFloor.Equal(end) {
				t.Fatal("final rejection changed work or lost floor")
			}
			if _, _, err = s.WindowsServiceActionViewExpected(context.Background(), pub, b.EndpointID, windowsaction.ServiceReviewBindingDigest(b), at); err == nil {
				t.Fatal("rollback revived rejected expiry")
			}
		})
	}
}

func TestWindowsServiceReviewRenewedLeafKeepsOriginalBindingAnchor(t *testing.T) {
	fixture, s, _, snapshot, anchor := activeWindowsStore(t, "tls")
	t.Cleanup(func() { s.Close() })
	at := time.Unix(testNow+20, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
	binding := windowsaction.Binding{ManagerID: snapshot.Binding.InstanceID, EndpointID: snapshot.Approval.DeviceID, IncarnationDigest: "sha256:" + anchor.CertificateHash(), KeyID: windowsaction.Digest(key.Public().(ed25519.PublicKey)), InstallationID: "broker_" + strings.Repeat("1", 32), GrantDigest: windowsaction.Digest([]byte("grant")), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("target"))}
	marker := &windowsActionSetupMarker{Version: "tracebolt.windows-service-action-setup.v1", Binding: binding, InitializedAt: at}
	intent := anchor.Intent()
	intent.IntentID = id("intent", 204)
	intent.RequestID = id("request", 204)
	intent.SerialHex = "000000000000000000000000000000cc"
	intent.NotAfter += 86400
	current := fixture.issue(t, intent)
	stop := errors.New("authority-only fixture rollback")
	err := s.transact(context.Background(), func(tx *transaction) error {
		c := tx.credentials[snapshot.InvitationID]
		c.Renewal = &renewalRecord{Current: renewalLeaf{Intent: current.Intent(), DER: current.DER(), CertificateHash: current.CertificateHash(), Generation: 2, ActivatedAt: at.Unix(), RequestID: intent.RequestID}, UpdatedAt: at.Unix()}
		tx.credentials[snapshot.InvitationID] = c
		renewed, err := s.windowsFullServicesAuthority(tx, snapshot.InvitationID, current.CertificateHash(), at)
		if err != nil || !validWindowsActionSetupMarker(renewed, marker, tx.currentCredentialNotAfter(renewed)) || renewed.Issuance.CertificateHash != anchor.CertificateHash() {
			t.Fatal("renewal changed immutable action anchor", err)
		}
		changed := *marker
		changed.Binding.IncarnationDigest = "sha256:" + current.CertificateHash()
		if validWindowsActionSetupMarker(renewed, &changed, tx.currentCredentialNotAfter(renewed)) {
			t.Fatal("renewed leaf replaced original anchor")
		}
		if _, err = s.windowsFullServicesAuthority(tx, snapshot.InvitationID, anchor.CertificateHash(), at); !errors.Is(err, enrollmentstate.ErrProof) {
			t.Fatal("retired leaf retained current authority", err)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatal(err)
	}
}
