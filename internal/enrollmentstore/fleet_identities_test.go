package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsmanaged"
	"reflect"
	"testing"
	"time"
)

func fleetIdentityCredentialBody(t *testing.T, s *Store, invitation string) []byte {
	t.Helper()
	var body []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, invitation).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func partialWindowsIdentityFrame(t *testing.T, sequence uint64, at time.Time) ([]byte, windowsmanaged.Snapshot) {
	t.Helper()
	var frame lanstore.Frame
	if err := json.Unmarshal(windowsStoreFrame(t, sequence, at), &frame); err != nil {
		t.Fatal(err)
	}
	frame.WindowsInventory.Hostname = windowsmanaged.Section[windowsmanaged.Hostname]{Source: "Synthetic unavailable hostname API", Scope: "Caller-visible computer name only", Quality: windowsmanaged.QualityUnavailable, Rows: []windowsmanaged.Hostname{}}
	frame.WindowsInventory.Network = windowsmanaged.Section[windowsmanaged.InterfaceAddress]{Source: "Synthetic interface API", Scope: "Caller-visible interface addresses; no socket or traffic data", Quality: windowsmanaged.QualityPartial, ObservedCount: 2, Rows: []windowsmanaged.InterfaceAddress{{Index: 7, Name: "Fixture Ethernet", Address: "192.0.2.8", PrefixLength: 24}, {Index: 7, Name: "Fixture Ethernet", Address: "2001:db8::8", PrefixLength: 64}}}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw, *frame.WindowsInventory
}

func TestFleetIdentitiesWindowsOriginalSectionsRetryAndRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f, s, path, identity, cert := activeWindowsStore(t, profile)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			raw, original := partialWindowsIdentityFrame(t, 1, at)
			first, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at)
			if err != nil {
				t.Fatal(err)
			}
			before := fleetIdentityCredentialBody(t, s, identity.InvitationID)
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s = f.open(t, path)
			retry, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
			if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) || !retry.CollectedAt.Equal(first.CollectedAt) || retry.Sequence != first.Sequence {
				t.Fatal("duplicate refreshed original receipt", err)
			}
			for _, age := range []time.Duration{0, 3 * time.Minute} {
				fleet, err := s.FleetIdentitiesView(ctx, at.Add(age))
				if err != nil || fleet.SchemaVersion != "tracebolt.fleet-identities.v2" || len(fleet.Items) != 1 || fleet.Items[0].Linux != nil || fleet.Items[0].Windows == nil {
					t.Fatal("Windows tagged union missing", err)
				}
				item := fleet.Items[0].Windows
				wantStatus := "fresh"
				if age > lanstore.SampleMaxAge {
					wantStatus = "stale"
				}
				if item.Status != wantStatus || item.Latest == nil || item.Sequence == nil || *item.Sequence != 1 || item.ReceivedAt == nil || !item.ReceivedAt.Equal(at) || !item.Latest.CollectedAt.Equal(at) || item.Latest.GenerationID != original.GenerationID {
					t.Fatal("projection changed capture, sequence or receipt", item)
				}
				if !reflect.DeepEqual(item.Latest.Hostname, original.Hostname) || !reflect.DeepEqual(item.Latest.Network, original.Network) {
					t.Fatal("projection changed scoped partial or unavailable source evidence")
				}
				encoded, err := json.Marshal(fleet)
				if err != nil {
					t.Fatal(err)
				}
				var object map[string]any
				if err = json.Unmarshal(encoded, &object); err != nil {
					t.Fatal(err)
				}
				wire := object["items"].([]any)[0].(map[string]any)
				if wire["sequence"] != "1" || len(wire["latest"].(map[string]any)) != 6 {
					t.Fatal("wire includes fields beyond original hostname/network identity")
				}
				for _, private := range [][]byte{[]byte("fixture.exe"), []byte("Fixture app"), []byte(`"processes"`), []byte(`"services"`), []byte(`"software"`), []byte(`"windowsNetwork"`)} {
					if bytes.Contains(encoded, private) {
						t.Fatal("nonidentity data escaped projection")
					}
				}
			}
			after := fleetIdentityCredentialBody(t, s, identity.InvitationID)
			if !bytes.Equal(before, after) {
				t.Fatal("read or duplicate changed persisted credential bytes")
			}
			var retained credential
			if err = json.Unmarshal(after, &retained); err != nil || !bytes.Equal(retained.Frame, raw) {
				t.Fatal("read changed saved frame", err)
			}
			ctl := control(identity, 20)
			ctl.Now = at.Add(4 * time.Minute).Unix()
			if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			fleet, err := s.FleetIdentitiesView(ctx, at.Add(4*time.Minute))
			if err != nil || len(fleet.Items) != 1 || fleet.Items[0].Windows.Status != "revoked" || fleet.Items[0].Windows.Latest != nil || fleet.Items[0].Windows.Sequence != nil {
				t.Fatal("revoked identity disclosed retained metadata", err)
			}
		})
	}
}

func TestFleetIdentitiesWindowsReadAdmissionCancellationAndPostCommitExpiry(t *testing.T) {
	_, s, _, identity, cert := activeWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	raw, _ := partialWindowsIdentityFrame(t, 1, at)
	if _, err := s.SaveObservation(context.Background(), identity.InvitationID, cert.CertificateHash(), raw, at); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.FleetIdentitiesView(canceled, at); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled fleet read accepted", err)
	}
	s.operationalReads <- struct{}{}
	if _, err := s.FleetIdentitiesView(context.Background(), at); !errors.Is(err, ErrOperationalBusy) {
		t.Fatal("fleet bypassed Windows operational-read admission", err)
	}
	<-s.operationalReads
	calls := 0
	expires := time.Unix(identity.Intent.NotAfter, 0).UTC()
	clock := func() time.Time {
		calls++
		if calls > 1 {
			return expires
		}
		return at
	}
	view, err := s.FleetIdentitiesView(WithSystemViewClock(context.Background(), clock), at)
	if err != nil || calls != 2 || len(view.Items) != 1 || view.Items[0].Windows.Status != "expired" || view.Items[0].Windows.Latest != nil {
		t.Fatal("post-commit authority expiry not applied", err, calls)
	}
	canceledAtCommit, cancelAtCommit := context.WithCancel(context.Background())
	defer cancelAtCommit()
	calls = 0
	cancelClock := func() time.Time {
		calls++
		if calls == 2 {
			cancelAtCommit()
		}
		return at
	}
	if _, err := s.FleetIdentitiesView(WithSystemViewClock(canceledAtCommit, cancelClock), at); !errors.Is(err, context.Canceled) {
		t.Fatal("post-commit cancellation accepted", err)
	}
	live, err := s.FleetIdentitiesView(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	if err = live.ValidateAt(expires); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal("encoded Windows identity survived authority expiry", err)
	}
	// Retention has its own boundary even if authority lasts longer.
	retained := *live.Items[0].Windows
	retained.certificateNotAfter = expires.Add(48 * time.Hour).Unix()
	retention := at.Add(24 * time.Hour)
	retained.ExpiresAt = &retention
	expired, err := retained.RecheckAt(retention)
	if err != nil || expired.Status != "expired" || expired.Latest != nil {
		t.Fatal("original capture retention extended", err)
	}
	if retained.Latest == nil || live.Items[0].Windows.Status != "fresh" {
		t.Fatal("validation mutated already encoded view")
	}
	rolled, err := expired.RecheckAt(at)
	if err != nil || !reflect.DeepEqual(rolled, expired) {
		t.Fatal("clock rollback revived expired metadata", err)
	}
	// The combined v2 projection admits both independent 25-member authorities.
	original := *live.Items[0].Windows
	_, linuxStore, _, _, _ := systemLongFixture(t)
	linux, err := linuxStore.FleetEndpointIdentityView(context.Background(), at)
	if err != nil || len(linux.Items) != 1 {
		t.Fatal("independent Linux authority fixture", err)
	}
	for _, count := range []int{FleetEndpointIdentityLimit + 1, FleetIdentitiesLimit} {
		combined := FleetIdentitiesView{SchemaVersion: "tracebolt.fleet-identities.v2", ServerNow: at, Items: []FleetIdentityItem{}}
		for i := 0; i < count; i++ {
			if i < FleetEndpointIdentityLimit {
				member := original
				member.DeviceID = fmt.Sprintf("agent_%032x", i+1)
				combined.Items = append(combined.Items, FleetIdentityItem{Windows: &member})
			} else {
				member := linux.Items[0]
				member.DeviceID = fmt.Sprintf("agent_%032x", i+1)
				combined.Items = append(combined.Items, FleetIdentityItem{Linux: &member})
			}
		}
		if _, err = combined.RecheckAt(at); err != nil {
			t.Fatal("bounded combined fleet rejected", count, err)
		}
	}
	live.Items = make([]FleetIdentityItem, FleetIdentitiesLimit+1)
	if _, err = live.RecheckAt(at); !errors.Is(err, ErrStorage) {
		t.Fatal("oversized fleet accepted", err)
	}
}

func TestFleetIdentitiesKeepsLinuxV1Projection(t *testing.T) {
	_, s, _, identity, cert := systemLongFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveSystemObservation(context.Background(), identity.InvitationID, cert.CertificateHash(), endpointRaw(t, identity.Approval.DeviceID, 1, at), at); err != nil {
		t.Fatal(err)
	}
	linux, err := s.FleetEndpointIdentityView(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := s.FleetIdentitiesView(context.Background(), at)
	if err != nil || len(fleet.Items) != 1 || fleet.Items[0].Windows != nil || fleet.Items[0].Linux == nil || !reflect.DeepEqual(*fleet.Items[0].Linux, linux.Items[0]) {
		t.Fatal("v2 changed Linux v1 item", err)
	}
	for _, invalid := range []FleetIdentityItem{{}, {Linux: &linux.Items[0], Windows: &WindowsFleetIdentityView{}}} {
		if _, err = json.Marshal(invalid); err == nil {
			t.Fatal("ambiguous union marshaled")
		}
	}
}
