package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/overviewgeneration"
	"localrmm/internal/overviewwire"
	"reflect"
	"strings"
	"testing"
	"time"

	"localrmm/internal/inventoryledger"
	"localrmm/internal/overviewledger"
)

// The one-row manifest and all identity material are invented by the fixture.
// No chunks are appended: a single maintenance step fully removes the stage.
func TestCompleteInventoryExpiredCleanupBeginRetry(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, snap.Approval.DeviceID, 1, 1, at)
	if _, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
		t.Fatal(err)
	}
	// Model a lost begin response followed by downtime past its original expiry.
	retryAt := at.Add(inventoryledger.StagingTTL - time.Nanosecond)
	pre, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, retryAt)
	if err != nil || pre.StartedAt != at || pre.ExpiresAt != at.Add(inventoryledger.StagingTTL) {
		t.Fatal("pre-expiry retry refreshed original lifetime", err)
	}
	now := at.Add(inventoryledger.StagingTTL)
	cleaned, err := s.MaintainInventoryStep(ctx, 0, now)
	if err != nil || !cleaned.GenerationRemoved {
		t.Fatalf("cleanup: %+v %v", cleaned, err)
	}
	oldTime, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, retryAt)
	if !errors.Is(err, enrollmentstate.ErrInvalid) || oldTime != (inventoryledger.BeginReceipt{}) {
		t.Fatal("pre-cleanup clock bypassed durable maintenance clock", err)
	}
	got, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, now)
	if !errors.Is(err, inventoryledger.ErrExpired) || got != (inventoryledger.BeginReceipt{}) {
		t.Errorf("expired begin retry must reject with zero receipt: %+v %v", got, err)
	}
	if _, err := s.InventoryView(ctx, snap.Approval.DeviceID, now); err != nil {
		t.Errorf("read after retry: %v", err)
	}
	s.Close()
	reopened, err := Open(path, f.config, f.issuerDER)
	if err != nil {
		t.Errorf("reopen after retry: %v", err)
	} else {
		reopened.Close()
	}
}

func TestCompleteOverviewExpiredCleanupBeginRetry(t *testing.T) {
	for _, section := range []string{"processes", "volumes"} {
		t.Run(section, func(t *testing.T) {

			f, s, path, snap, cert := overviewFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			b, m, _ := expiryCleanupOverviewGeneration(t, snap.Approval.DeviceID, section, 1, 1, at)
			if _, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
				t.Fatal(err)
			}
			retryAt := at.Add(overviewledger.StagingTTL - time.Nanosecond)
			pre, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, retryAt)
			if err != nil || pre.StartedAt != at || pre.ExpiresAt != at.Add(overviewledger.StagingTTL) {
				t.Fatal("pre-expiry retry refreshed original lifetime", err)
			}
			now := at.Add(overviewledger.StagingTTL)
			cleaned, err := s.MaintainInventoryStep(ctx, map[string]uint64{"processes": 1, "volumes": 2}[section], now)
			if err != nil || !cleaned.GenerationRemoved {
				t.Fatalf("cleanup: %+v %v", cleaned, err)
			}
			oldTime, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, retryAt)
			if !errors.Is(err, enrollmentstate.ErrInvalid) || oldTime != (overviewledger.BeginReceipt{}) {
				t.Fatal("pre-cleanup clock bypassed durable maintenance clock", err)
			}
			got, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, now)
			if !errors.Is(err, overviewledger.ErrExpired) || got != (overviewledger.BeginReceipt{}) {
				t.Errorf("expired begin retry must reject with zero receipt: %+v %v", got, err)
			}
			if _, err := s.OverviewView(ctx, snap.Approval.DeviceID, now); err != nil {
				t.Errorf("read after retry: %v", err)
			}
			s.Close()
			reopened, err := Open(path, f.config, f.issuerDER)
			if err != nil {
				t.Errorf("reopen after retry: %v", err)
			} else {
				reopened.Close()
			}

		})
	}
}

func TestCompleteInventoryExpiredCleanupAbort(t *testing.T) {
	for _, previous := range []bool{false, true} {
		name := "first-transfer"
		if previous {
			name = "preserves-current"
		}
		t.Run(name, func(t *testing.T) {
			f, s, path, snap, cert := completeFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			seq := uint64(1)
			var old InventoryBinding
			if previous {
				prior, pm, chunks := completeGeneration(t, snap.Approval.DeviceID, seq, 1, at)
				promoteComplete(t, s, snap, cert, prior, pm, chunks, at)
				old = prior
				seq++
				at = at.Add(time.Second)
			}
			b, m, _ := completeGeneration(t, snap.Approval.DeviceID, seq, 1, at)
			if _, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
				t.Fatal(err)
			}
			now := at.Add(inventoryledger.StagingTTL)
			cleaned, err := s.MaintainInventoryStep(ctx, 0, now)
			if err != nil || !cleaned.GenerationRemoved {
				t.Fatalf("cleanup: %+v %v", cleaned, err)
			}
			before, err := s.InventoryStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, now)
			if err != nil || before.Transfer == nil || before.Transfer.State != "expired" || before.CompleteBinding != old {
				t.Fatalf("expired status: %+v %v", before, err)
			}
			// Authentication, full tuple binding, monotone time and current leaf stay mandatory.
			if err := s.InventoryAbort(ctx, snap.InvitationID, strings.Repeat("1", 64), b, now); !errors.Is(err, enrollmentstate.ErrProof) {
				t.Fatal("wrong certificate abort", err)
			}
			for _, field := range []string{"sequence", "generation", "hash"} {
				bad := b
				switch field {
				case "sequence":
					bad.Sequence++
				case "generation":
					bad.GenerationID = id("sample", 991)
				case "hash":
					bad.ManifestHash = strings.Repeat("1", 64)
				}
				if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), bad, now); !errors.Is(err, inventoryledger.ErrConflict) {
					t.Fatal("wrong binding abort", field, err)
				}
			}
			if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(-time.Nanosecond)); !errors.Is(err, enrollmentstate.ErrInvalid) {
				t.Fatal("backward abort", err)
			}
			if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, time.Unix(snap.Intent.NotAfter, 0).UTC()); !errors.Is(err, enrollmentstate.ErrExpired) {
				t.Fatal("expired certificate abort", err)
			}
			if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now); err != nil {
				t.Fatal("abort expired cleaned transfer", err)
			}
			after, err := s.InventoryStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, now)
			if err != nil || after.Transfer == nil || after.Transfer.State != "failed" || after.Sequence != seq {
				t.Fatalf("terminal status: %+v %v", after, err)
			}
			if !reflect.DeepEqual(after.Transfer.Manifest, before.Transfer.Manifest) || after.Transfer.StartedAt != before.Transfer.StartedAt || after.Transfer.ExpiresAt != before.Transfer.ExpiresAt || after.CompleteBinding != old || !reflect.DeepEqual(after.Complete, before.Complete) {
				t.Fatal("abort changed retained manifest, original lifetime or previous complete")
			}
			s.Close()
			s = f.open(t, path)
			if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(time.Second)); err != nil {
				t.Fatal("durable abort retry", err)
			}
			got, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, now.Add(time.Second))
			if !errors.Is(err, inventoryledger.ErrConflict) || got != (inventoryledger.BeginReceipt{}) {
				t.Fatal("aborted floor reused", err)
			}
			next, nm, chunks := completeGeneration(t, snap.Approval.DeviceID, seq+1, 1, now.Add(time.Second))
			promoteComplete(t, s, snap, cert, next, nm, chunks, now.Add(time.Second))
			progressed, err := s.InventoryStatus(ctx, snap.InvitationID, cert.CertificateHash(), next, now.Add(time.Second))
			if err != nil || progressed.CompleteBinding != next || progressed.Complete == nil || progressed.Complete.Manifest.ObservedCount != 1 {
				t.Fatal("higher sequence did not progress", err)
			}
			if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, now.Add(time.Second)); !errors.Is(err, inventoryledger.ErrConflict) {
				t.Fatal("completed abort", err)
			}
		})
	}
}

func TestCompleteOverviewExpiredCleanupAbort(t *testing.T) {
	for _, section := range []string{"processes", "volumes"} {
		t.Run(section, func(t *testing.T) {

			for _, previous := range []bool{false, true} {
				name := "first-transfer"
				if previous {
					name = "preserves-current"
				}
				t.Run(name, func(t *testing.T) {
					f, s, path, snap, cert := overviewFixture(t)
					ctx := context.Background()
					at := time.Unix(testNow+10, 0).UTC()
					seq := uint64(1)
					var old OverviewBinding
					if previous {
						prior, pm, chunks := expiryCleanupOverviewGeneration(t, snap.Approval.DeviceID, section, seq, 1, at)
						promoteOverview(t, s, snap, cert, prior, pm, chunks, at)
						old = prior
						seq++
						at = at.Add(time.Second)
					}
					b, m, _ := expiryCleanupOverviewGeneration(t, snap.Approval.DeviceID, section, seq, 1, at)
					if _, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
						t.Fatal(err)
					}
					now := at.Add(overviewledger.StagingTTL)
					cleaned, err := s.MaintainInventoryStep(ctx, map[string]uint64{"processes": 1, "volumes": 2}[section], now)
					if err != nil || !cleaned.GenerationRemoved {
						t.Fatalf("cleanup: %+v %v", cleaned, err)
					}
					before, err := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, now)
					if err != nil || before.Transfer == nil || before.Transfer.State != "expired" || before.CompleteBinding != old {
						t.Fatalf("expired status: %+v %v", before, err)
					}
					// Authentication, full tuple binding, monotone time and current leaf stay mandatory.
					if err := s.OverviewAbort(ctx, snap.InvitationID, strings.Repeat("1", 64), b, now); !errors.Is(err, enrollmentstate.ErrProof) {
						t.Fatal("wrong certificate abort", err)
					}
					for _, field := range []string{"sequence", "generation", "hash"} {
						bad := b
						switch field {
						case "sequence":
							bad.Sequence++
						case "generation":
							bad.GenerationID = id("sample", 991)
						case "hash":
							bad.ManifestHash = strings.Repeat("1", 64)
						}
						if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), bad, now); !errors.Is(err, overviewledger.ErrConflict) {
							t.Fatal("wrong binding abort", field, err)
						}
					}
					if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(-time.Nanosecond)); !errors.Is(err, enrollmentstate.ErrInvalid) {
						t.Fatal("backward abort", err)
					}
					if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, time.Unix(snap.Intent.NotAfter, 0).UTC()); !errors.Is(err, enrollmentstate.ErrExpired) {
						t.Fatal("expired certificate abort", err)
					}
					if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now); err != nil {
						t.Fatal("abort expired cleaned transfer", err)
					}
					after, err := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, now)
					if err != nil || after.Transfer == nil || after.Transfer.State != "failed" || after.Sequence != seq {
						t.Fatalf("terminal status: %+v %v", after, err)
					}
					if !reflect.DeepEqual(after.Transfer.Manifest, before.Transfer.Manifest) || after.Transfer.StartedAt != before.Transfer.StartedAt || after.Transfer.ExpiresAt != before.Transfer.ExpiresAt || after.CompleteBinding != old || !reflect.DeepEqual(after.Complete, before.Complete) {
						t.Fatal("abort changed retained manifest, original lifetime or previous complete")
					}
					s.Close()
					s = f.open(t, path)
					if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(time.Second)); err != nil {
						t.Fatal("durable abort retry", err)
					}
					got, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, now.Add(time.Second))
					if !errors.Is(err, overviewledger.ErrConflict) || got != (overviewledger.BeginReceipt{}) {
						t.Fatal("aborted floor reused", err)
					}
					next, nm, chunks := expiryCleanupOverviewGeneration(t, snap.Approval.DeviceID, section, seq+1, 1, now.Add(time.Second))
					promoteOverview(t, s, snap, cert, next, nm, chunks, now.Add(time.Second))
					progressed, err := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), next, now.Add(time.Second))
					if err != nil || progressed.CompleteBinding != next || progressed.Complete == nil || progressed.Complete.Manifest.ObservedCount != 1 {
						t.Fatal("higher sequence did not progress", err)
					}
					if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), next, now.Add(time.Second)); !errors.Is(err, overviewledger.ErrConflict) {
						t.Fatal("completed abort", err)
					}
				})
			}

		})
	}
}

func TestCompleteInventoryMissingRetryCannotCreateBeforeExpiry(t *testing.T) {
	f, s, path, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, snap.Approval.DeviceID, 1, 1, at)
	if _, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
		t.Fatal(err)
	}
	// Deliberately isolate the non-creating guard from the maintenance clock:
	// remove only this synthetic ledger stage using its real bounded cleanup,
	// leaving the fixture authority's original clock untouched. Production
	// maintenance also records a watermark, covered in the normal retry test.
	if err := s.transact(ctx, func(tx *transaction) error {
		cleaned, err := completeLedger().Cleanup(ctx, tx.conn, snap.Approval.DeviceID, b.GenerationID, at.Add(inventoryledger.StagingTTL))
		if err != nil {
			return err
		}
		if !cleaned.Done {
			t.Fatal("tiny synthetic stage not removed")
		}
		_, err = tx.conn.ExecContext(ctx, `DELETE FROM enrollment_inventory_generations WHERE device=? AND generation=?`, snap.Approval.DeviceID, b.GenerationID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
	if !errors.Is(err, ErrStorage) || got != (inventoryledger.BeginReceipt{}) {
		t.Error("missing generation recreated with stale timestamp", err)
	}
	if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at); !errors.Is(err, inventoryledger.ErrNotFound) {
		t.Error("missing-before-expiry accepted as terminal", err)
	}
	if err := s.transact(ctx, func(tx *transaction) error {
		r := tx.inventory[snap.InvitationID]
		if r.Binding != b || r.State != "pending" || r.StartedAt != at || r.LastAt != at || r.MaintenanceAt != nil {
			t.Error("failed calls changed retained floor")
		}
		return nil
	}); err != nil {
		t.Fatal("failed retry damaged store", err)
	}
	s.Close()
	s = f.open(t, path)
	now := at.Add(inventoryledger.StagingTTL)
	if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now); err != nil {
		t.Fatal("exact expiry terminal recovery", err)
	}
}

func TestCompleteOverviewMissingRetryCannotCreateBeforeExpiry(t *testing.T) {
	for _, section := range []string{"processes", "volumes"} {
		t.Run(section, func(t *testing.T) {

			f, s, path, snap, cert := overviewFixture(t)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			b, m, _ := expiryCleanupOverviewGeneration(t, snap.Approval.DeviceID, section, 1, 1, at)
			if _, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
				t.Fatal(err)
			}
			// Deliberately isolate the non-creating guard from the maintenance clock:
			// remove only this synthetic ledger stage using its real bounded cleanup,
			// leaving the fixture authority's original clock untouched. Production
			// maintenance also records a watermark, covered in the normal retry test.
			if err := s.transact(ctx, func(tx *transaction) error {
				cleaned, err := overviewLedger().Cleanup(ctx, tx.conn, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID, at.Add(overviewledger.StagingTTL))
				if err != nil {
					return err
				}
				if !cleaned.Done {
					t.Fatal("tiny synthetic stage not removed")
				}
				_, err = tx.conn.ExecContext(ctx, `DELETE FROM enrollment_overview_generations WHERE device=? AND generation=?`, overviewDevice(snap.Approval.DeviceID, b.Section), b.GenerationID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			got, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at)
			if !errors.Is(err, ErrStorage) || got != (overviewledger.BeginReceipt{}) {
				t.Error("missing generation recreated with stale timestamp", err)
			}
			if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, at); !errors.Is(err, overviewledger.ErrNotFound) {
				t.Error("missing-before-expiry accepted as terminal", err)
			}
			if err := s.transact(ctx, func(tx *transaction) error {
				r := tx.overview[overviewRecordKey(snap.InvitationID, b.Section)]
				if r.Binding != b || r.State != "pending" || r.StartedAt != at || r.LastAt != at || r.MaintenanceAt != nil {
					t.Error("failed calls changed retained floor")
				}
				return nil
			}); err != nil {
				t.Fatal("failed retry damaged store", err)
			}
			s.Close()
			s = f.open(t, path)
			now := at.Add(overviewledger.StagingTTL)
			if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now); err != nil {
				t.Fatal("exact expiry terminal recovery", err)
			}

		})
	}
}

// An ordinary one-row mount fixture, never a read of the machine's mount table.
func expiryCleanupOverviewGeneration(t *testing.T, device, section string, seq uint64, n int, at time.Time) (OverviewBinding, overviewgeneration.Manifest, []overviewgeneration.Chunk) {
	t.Helper()
	if section == "processes" {
		return overviewGeneration(t, device, seq, n, at)
	}
	if n != 1 {
		t.Fatal("expiry fixture must remain tiny")
	}
	source := completeoverview.Empty(id("sample", 998), at, completeoverview.ReasonReadFailed)
	count := uint64(1)
	source.Volumes.Meta = completeoverview.SectionMeta{GenerationID: source.GenerationID, Coverage: completeoverview.Complete, Reason: completeoverview.ReasonNone, ObservedCount: &count, CountExact: true, FieldCoverage: completeoverview.FieldCoverage{Denied: 1}}
	source.Volumes.Items = []completeoverview.Volume{{ID: "mount_1", MountPoint: "/", Filesystem: "ext4", Kind: "local", FilesystemGroup: "fs_8_1", CapacityScope: "agent-mount-namespace", Measurement: completeoverview.Observation{Status: completeoverview.Denied, Reason: completeoverview.ReasonPermissionDenied}}}
	generation, err := overviewwire.GenerationID(device, section, seq)
	if err != nil {
		t.Fatal(err)
	}
	manifest, chunks, err := overviewgeneration.Build(context.Background(), source, section, generation, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := overviewgeneration.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return OverviewBinding{section, seq, generation, digest}, manifest, chunks
}

func TestCompleteInventoryExpiredCleanupAbortRejectsRevocation(t *testing.T) {
	_, s, _, snap, cert := completeFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := completeGeneration(t, snap.Approval.DeviceID, 1, 1, at)
	if _, err := s.InventoryBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
		t.Fatal(err)
	}
	now := at.Add(inventoryledger.StagingTTL)
	if cleaned, err := s.MaintainInventoryStep(ctx, 0, now); err != nil || !cleaned.GenerationRemoved {
		t.Fatal("cleanup", err)
	}
	revoke := control(snap, 99)
	revoke.Now = now.Add(time.Second).Unix()
	if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if err := s.InventoryAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(time.Second)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("revoked cleanup abort", err)
	}
}

func TestCompleteOverviewExpiredCleanupAbortRejectsRevocation(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	b, m, _ := overviewGeneration(t, snap.Approval.DeviceID, 1, 1, at)
	if _, err := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, at); err != nil {
		t.Fatal(err)
	}
	now := at.Add(overviewledger.StagingTTL)
	if cleaned, err := s.MaintainInventoryStep(ctx, 1, now); err != nil || !cleaned.GenerationRemoved {
		t.Fatal("cleanup", err)
	}
	revoke := control(snap, 99)
	revoke.Now = now.Add(time.Second).Unix()
	if _, err := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if err := s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, now.Add(time.Second)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("revoked cleanup abort", err)
	}
}
