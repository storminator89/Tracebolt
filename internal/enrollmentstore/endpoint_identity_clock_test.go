package enrollmentstore

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestEndpointMetadataOriginalAgeAcrossReadBoundaries(t *testing.T) {
	for _, boundary := range []string{"admission", "sql_wait", "commit", "output"} {
		for _, horizon := range []string{"stale", "retention", "certificate"} {
			t.Run(boundary+"/"+horizon, func(t *testing.T) {
				_, s, _, snap, cert := systemLongFixture(t)
				defer s.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				at := time.Unix(testNow+10, 0).UTC()
				if horizon == "certificate" {
					at = time.Unix(snap.Intent.NotAfter, 0).UTC().Add(-time.Minute)
				}
				device := snap.Approval.DeviceID
				if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), endpointRaw(t, device, 1, at), at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				// A later ordinary system frame cannot refresh endpoint identity.
				ordinaryAt := at.Add(2 * time.Second)
				saveSystemFixture(t, s, snap, cert, 2, systemFixtureSnapshot(t, device, 2, 0, ordinaryAt), ordinaryAt)
				before := journalBody(t, s, snap.InvitationID)
				expiry, want := at.Add(SystemMaxAge+time.Nanosecond), "stale"
				if horizon == "retention" {
					expiry, want = at.Add(SystemRetention), "expired"
				}
				if horizon == "certificate" {
					expiry, want = time.Unix(snap.Intent.NotAfter, 0).UTC(), "expired"
				}
				initial := expiry.Add(-time.Nanosecond)
				clock := &overviewFixtureClock{}
				clock.set(initial)
				var calls atomic.Int64
				readCtx := WithSystemViewClock(ctx, func() time.Time {
					if boundary == "commit" && calls.Add(1) > 1 {
						clock.set(expiry)
					}
					return clock.now()
				})
				var view EndpointIdentityView
				call := func() error { var err error; view, err = s.EndpointIdentityView(readCtx, device, initial); return err }
				var err error
				switch boundary {
				case "admission":
					held, e := s.inventoryAdmission(ctx)
					if e != nil {
						t.Fatal(e)
					}
					done := make(chan error, 1)
					go func() { done <- call() }()
					waitSystemMetadataReader(t, s, ctx)
					if clock.calls.Load() != 0 {
						t.Fatal("clock sampled before admission")
					}
					clock.set(expiry)
					held()
					err = <-done
				case "sql_wait":
					err = afterOverviewConnectionWait(t, s, func() {
						if clock.calls.Load() != 0 {
							t.Error("clock sampled before authority transaction")
						}
						clock.set(expiry)
					}, call)
				default:
					err = call()
				}
				if boundary == "output" && err == nil {
					view, err = view.RecheckAt(expiry)
				}
				if err != nil || view.Status != want || !view.ServerNow.Equal(expiry) {
					t.Fatal("stale authority/source age escaped", view.Status, err)
				}
				if horizon == "certificate" && (boundary == "admission" || boundary == "sql_wait") {
					if view.Latest != nil || view.Sequence != nil || view.ReceivedAt != nil || view.ExpiresAt != nil {
						t.Fatal("identity denial exposed metadata")
					}
				} else {
					if view.Sequence == nil || *view.Sequence != 1 || view.ReceivedAt == nil || !view.ReceivedAt.Equal(at.Add(time.Second)) || view.ExpiresAt == nil || !view.ExpiresAt.Equal(at.Add(SystemRetention)) {
						t.Fatal("read changed endpoint receipt, sequence or retention")
					}
					if want == "stale" && (view.Latest == nil || !view.Latest.CollectedAt.Equal(at)) || want == "expired" && view.Latest != nil {
						t.Fatal("read refreshed source age or exposed expired payload")
					}
				}
				rolled, err := view.RecheckAt(at)
				if err != nil || !reflect.DeepEqual(rolled, view) {
					t.Fatal("output clock rollback revived metadata", err)
				}
				if after := journalBody(t, s, snap.InvitationID); !bytes.Equal(before, after) {
					t.Fatal("read changed durable observation/floors")
				}
			})
		}
	}
}

func TestEndpointMetadataQueuedRevocationAndUntrustedOutput(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), endpointRaw(t, snap.Approval.DeviceID, 1, at), at); err != nil {
		t.Fatal(err)
	}
	held, err := s.inventoryAdmission(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		view EndpointIdentityView
		err  error
	}
	done := make(chan result, 1)
	go func() {
		v, err := s.EndpointIdentityView(WithSystemViewClock(ctx, func() time.Time { return at.Add(2 * time.Second) }), snap.Approval.DeviceID, at)
		done <- result{v, err}
	}()
	waitSystemMetadataReader(t, s, ctx)
	command := control(snap, 51)
	command.Now = at.Add(time.Second).Unix()
	if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: command, State: enrollmentstate.Revoked}); err != nil {
		held()
		t.Fatal(err)
	}
	held()
	out := <-done
	if out.err != nil || out.view.Status != "revoked" || out.view.Latest != nil || out.view.Sequence != nil {
		t.Fatal("queued read used revoked authority", out.err)
	}
	if rolled, err := out.view.RecheckAt(time.Unix(snap.Intent.NotAfter, 0).UTC()); err != nil || rolled.Status != "revoked" || rolled.Latest != nil {
		t.Fatal("later clock revived revoked metadata", err)
	}
	if view, err := (EndpointIdentityView{Status: "fresh", ServerNow: at}).RecheckAt(at); !errors.Is(err, ErrStorage) || !reflect.DeepEqual(view, EndpointIdentityView{}) {
		t.Fatal("wire-only fields manufactured read authority")
	}
}
