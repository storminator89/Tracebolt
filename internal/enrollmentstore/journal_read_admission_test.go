package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/journalrequest"
	"testing"
	"time"
)

func TestJournalStatusReadAdmissionAndClock(t *testing.T) {
	for _, kind := range []string{"request", "generation"} {
		for _, boundary := range []string{"admission", "sql", "commit", "certificate", "cancel", "timeout", "latch_failure"} {
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				_, s, _, snap, cert, at := journalFixture(t)
				report := generationReport(at, 1, 1)
				if _, err := s.AcceptJournalGeneration(context.Background(), snap.InvitationID, cert.CertificateHash(), report, at); err != nil {
					t.Fatal(err)
				}
				description, err := s.CreateJournalRequestWithGeneration(context.Background(), snap.Approval.DeviceID, 0, journalQuery(at), report.Tuple, at)
				if err != nil {
					t.Fatal(err)
				}
				expiry := description.ExpiresAt
				if kind == "generation" {
					expiry = at.Add(JournalGenerationMaxAge)
				}
				read := func(ctx context.Context) (string, error) {
					if kind == "request" {
						v, e := s.JournalRequestStatus(ctx, snap.Approval.DeviceID, at)
						return string(v.State), e
					}
					v, e := s.JournalGenerationStatus(ctx, snap.Approval.DeviceID, at)
					if e != nil || v == nil {
						return "", e
					}
					if v.Fresh {
						return "fresh", nil
					}
					return "expired", nil
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				clock := &overviewFixtureClock{}
				clock.set(at)
				calls := 0
				ctx = WithSystemViewClock(ctx, func() time.Time {
					calls++
					if (boundary == "commit" || boundary == "latch_failure") && calls >= 2 {
						clock.set(expiry)
					}
					if boundary == "certificate" && calls >= 2 {
						clock.set(time.Unix(snap.Intent.NotAfter, 0))
					}
					if boundary == "cancel" && calls == 2 {
						cancel()
					}
					if boundary == "latch_failure" && calls == 2 {
						if _, e := s.db.Exec(`CREATE TRIGGER reject_journal_latch BEFORE UPDATE ON enrollment_system_authority BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
							t.Fatal(e)
						}
					}
					return clock.now()
				})
				if boundary == "admission" || boundary == "timeout" {
					release, e := s.inventoryAdmission(ctx)
					if e != nil {
						t.Fatal(e)
					}
					type result struct {
						state string
						err   error
					}
					done := make(chan result, 1)
					go func() { state, e := read(ctx); done <- result{state, e} }()
					waitSystemMetadataReader(t, s, ctx)
					if _, e := s.SystemView(ctx, snap.Approval.DeviceID, at); !errors.Is(e, ErrInventoryBusy) {
						t.Fatal("second shared reader admitted", e)
					}
					if boundary == "timeout" {
						cancel()
					} else {
						clock.set(expiry)
					}
					release()
					out := <-done
					if boundary == "timeout" {
						if !errors.Is(out.err, context.Canceled) || out.state != "" {
							t.Fatal("cancel did not withhold", out.err)
						}
					} else if out.err != nil || out.state != "expired" {
						t.Fatal("queued expiry not committed", out.state, out.err)
					}
				} else if boundary == "sql" {
					held, e := s.db.Conn(ctx)
					if e != nil {
						t.Fatal(e)
					}
					before := s.db.Stats().WaitCount
					type result struct {
						state string
						err   error
					}
					done := make(chan result, 1)
					go func() { state, e := read(ctx); done <- result{state, e} }()
					for s.db.Stats().WaitCount == before {
						select {
						case <-ctx.Done():
							t.Fatal("read did not wait SQL")
						case <-time.After(time.Millisecond):
						}
					}
					clock.set(expiry)
					held.Close()
					out := <-done
					if out.err != nil || out.state != "expired" {
						t.Fatal("SQL wait kept old authority clock", out.state, out.err)
					}
				} else {
					state, e := read(ctx)
					switch boundary {
					case "certificate":
						if !errors.Is(e, enrollmentstate.ErrExpired) || state != "" {
							t.Fatal("certificate expiry returned output", e)
						}
					case "cancel":
						if !errors.Is(e, context.Canceled) || state != "" {
							t.Fatal("canceled postcommit output", e)
						}
					case "latch_failure":
						if e == nil || state != "" {
							t.Fatal("uncommitted expiry returned output")
						}
					default:
						if e != nil || state != "expired" {
							t.Fatal("postcommit expiry not committed", state, e)
						}
					}
				}
				if len(s.inventoryCalls) != 0 || len(s.systemMetadataReads) != 0 {
					t.Fatal("read leaked admission")
				}
				if boundary == "admission" || boundary == "sql" || boundary == "commit" {
					state, e := read(WithSystemViewClock(context.Background(), func() time.Time { return at }))
					if e != nil || state != "expired" {
						t.Fatal("clock rollback revived observed expiry", state, e)
					}
					if kind == "request" {
						v, e := s.JournalRequestStatus(context.Background(), snap.Approval.DeviceID, expiry)
						if e != nil || v.Description != description || v.Description.Identity.Sequence != 1 || v.State != journalrequest.Expired {
							t.Fatal("expiry changed original request/floor", e)
						}
					}
				}
			})
		}
	}
}
