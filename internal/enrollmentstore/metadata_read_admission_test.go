package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"reflect"
	"testing"
	"time"
)

// The complete-profile metadata cohort shares one total waiting/read permit.
// Real maintenance owns the existing writer permit while its sole connection is
// held. All rows and identities are synthetic and the store is temporary.
func TestMetadataReadCohortSharesMaintenanceHandoff(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	at := time.Unix(testNow+10, 0).UTC()
	device := snap.Approval.DeviceID
	if err := s.InitializeCompleteUpdates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSystemObservation(ctx, snap.InvitationID, cert.CertificateHash(), endpointRaw(t, device, 1, at), at); err != nil {
		t.Fatal(err)
	}
	b, m, chunks := overviewGeneration(t, device, 1, 2, at)
	promoteOverview(t, s, snap, cert, b, m, chunks, at)
	ub, um, uc := updatesGenerationFixture(t, device, 1, 2, at)
	promoteCompleteUpdates(t, s, snap, cert, ub, um, uc, at)
	copied := *s
	readers := []struct {
		name string
		read func(context.Context) (any, error)
		zero any
	}{
		{"overview", func(ctx context.Context) (any, error) { return copied.OverviewView(ctx, device, at) }, OverviewStatus{}},
		{"endpoint", func(ctx context.Context) (any, error) { return copied.EndpointIdentityView(ctx, device, at) }, EndpointIdentityView{}},
		{"complete_updates", func(ctx context.Context) (any, error) { return copied.CompleteUpdatesView(ctx, device, at) }, CompleteUpdatesStatus{}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			beforeView, err := reader.read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			held, err := s.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			before := s.db.Stats().WaitCount
			maintained := make(chan error, 1)
			go func() { _, err := s.MaintainInventoryStep(ctx, 0, at); maintained <- err }()
			for s.db.Stats().WaitCount == before {
				select {
				case <-ctx.Done():
					t.Fatal("maintenance did not queue")
				case <-time.After(time.Millisecond):
				}
			}
			type result struct {
				view any
				err  error
			}
			done := make(chan result, 1)
			go func() { v, err := reader.read(ctx); done <- result{v, err} }()
			waitSystemMetadataReader(t, s, ctx)
			for _, excess := range readers {
				v, err := excess.read(ctx)
				if !errors.Is(err, ErrInventoryBusy) || !reflect.DeepEqual(v, excess.zero) {
					t.Fatalf("%s exceeded the shared read budget: %v", excess.name, err)
				}
			}
			for _, read := range []func() error{
				func() error { _, err := s.SystemView(ctx, device, at); return err },
				func() error { _, err := s.InventoryView(ctx, device, at); return err },
				func() error { _, err := s.JournalRequestStatus(ctx, device, at); return err },
				func() error { _, err := s.JournalGenerationStatus(ctx, device, at); return err },
			} {
				if err := read(); !errors.Is(err, ErrInventoryBusy) {
					t.Fatal("existing metadata read exceeded total waiter budget", err)
				}
			}
			if _, err := s.MaintainInventoryStep(ctx, 0, at); !errors.Is(err, ErrInventoryBusy) {
				t.Fatal("maintenance gained a queue", err)
			}
			select {
			case out := <-done:
				t.Fatal("reader failed instead of waiting for maintenance", out.err)
			default:
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-maintained; err != nil {
				t.Fatal(err)
			}
			out := <-done
			if out.err != nil || !reflect.DeepEqual(beforeView, out.view) {
				t.Fatal("handoff lost authorized original metadata", out.err)
			}
			if len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
				t.Fatal("metadata read leaked admission")
			}
		})
	}
}

func TestMetadataReadCohortCancellationAndCertificateWait(t *testing.T) {
	for _, kind := range []string{"overview", "endpoint", "complete_updates"} {
		for _, boundary := range []string{"cancel", "certificate"} {
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				_, s, _, snap, _ := overviewFixture(t)
				defer s.Close()
				if err := s.InitializeCompleteUpdates(context.Background()); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				expiry := time.Unix(snap.Intent.NotAfter, 0).UTC()
				at := expiry.Add(-time.Nanosecond)
				clock := &overviewFixtureClock{}
				clock.set(at)
				ctx = WithSystemViewClock(WithOverviewClock(ctx, clock.now), clock.now)
				held, err := s.inventoryAdmission(ctx)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					var err error
					switch kind {
					case "overview":
						v, e := s.OverviewView(ctx, snap.Approval.DeviceID, at)
						err = e
						if !reflect.DeepEqual(v, OverviewStatus{}) {
							err = ErrStorage
						}
					case "complete_updates":
						v, e := s.CompleteUpdatesView(ctx, snap.Approval.DeviceID, at)
						err = e
						if !reflect.DeepEqual(v, CompleteUpdatesStatus{}) {
							err = ErrStorage
						}
					case "endpoint":
						v, e := s.EndpointIdentityView(ctx, snap.Approval.DeviceID, at)
						err = e
						if e == nil && (v.Status != "expired" || v.Latest != nil || !v.ServerNow.Equal(expiry)) || e != nil && !reflect.DeepEqual(v, EndpointIdentityView{}) {
							err = ErrStorage
						}
					}
					done <- err
				}()
				waitSystemMetadataReader(t, s, ctx)
				if clock.calls.Load() != 0 {
					t.Fatal("sampled authority before admission")
				}
				if boundary == "cancel" {
					cancel()
				} else {
					clock.set(expiry)
				}
				held()
				err = <-done
				want := error(enrollmentstate.ErrExpired)
				if boundary == "cancel" {
					want = context.Canceled
				} else if kind == "endpoint" {
					want = nil
				}
				if !errors.Is(err, want) {
					t.Fatal("wrong queued authority result", err)
				}
				if len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
					t.Fatal("admission leaked")
				}
			})
		}
	}
}
