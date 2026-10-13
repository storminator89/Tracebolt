package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/macosinventorywire"
)

type macOSInventoryClockKey struct{}
type macOSInventoryOriginKey struct{}

// Trusted boundary adapters only; never install values from request fields.
func WithMacOSInventoryClock(ctx context.Context, now func() time.Time) context.Context {
	return context.WithValue(ctx, macOSInventoryClockKey{}, now)
}
func WithMacOSInventoryIngressOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, macOSInventoryOriginKey{}, origin)
}
func macOSNow(ctx context.Context, floor time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(floor) {
		return time.Time{}, enrollmentstate.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if clock, ok := ctx.Value(macOSInventoryClockKey{}).(func() time.Time); ok {
		if clock == nil {
			return time.Time{}, enrollmentstate.ErrInvalid
		}
		at := clock().UTC()
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		if !validStoreTime(at) || at.Before(floor) {
			return time.Time{}, enrollmentstate.ErrInvalid
		}
		return at, nil
	}
	return floor.UTC(), nil
}
func macOSInventoryBinding(snap enrollmentstate.Snapshot, origin string) macosinventorywire.Binding {
	sum := sha256.Sum256([]byte("tracebolt.sender-binding.macos-inventory.v1\nmacos-read-inventory-v1\ntls\n" + origin + "\n" + snap.Issuance.CertificateHash + "\n" + snap.Approval.DeviceID))
	return macosinventorywire.Binding{Platform: "darwin", Profile: macosinventorywire.Profile, DeviceID: snap.Approval.DeviceID, SenderBinding: hex.EncodeToString(sum[:])}
}
func (s *Store) macOSInventoryAdmission(ctx context.Context) (func(), error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return nil, enrollmentstate.ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if s.config.Platform != "darwin" || s.config.Binding.Profile != "tls" || s.config.Binding.CollectionProfile != macosinventorywire.Profile {
		return nil, enrollmentstate.ErrProof
	}
	select {
	case s.inventoryCalls <- struct{}{}:
		return func() { <-s.inventoryCalls }, nil
	default:
		return nil, ErrInventoryBusy
	}
}
func (s *Store) macOSInventoryAuthority(t *transaction, id, cert string, now time.Time) (enrollmentstate.Snapshot, error) {
	snap, e := t.engine.Get(id)
	if e != nil {
		return snap, e
	}
	if snap.Platform != "darwin" || snap.Binding.Profile != "tls" || snap.Binding.CollectionProfile != macosinventorywire.Profile {
		return snap, enrollmentstate.ErrProof
	}
	if e = t.authorizeCurrentCredential(snap, cert, now); e != nil {
		return snap, e
	}
	return snap, nil
}
func macOSInventorySourceStatuses(r macosinventorywire.Report) MacOSInventorySources {
	return MacOSInventorySources{r.Snapshot.Hardware.Status, r.Snapshot.Receipts.Status, r.Snapshot.Processes.Status, r.Snapshot.Network.IPv4.Status, r.Snapshot.Network.IPv6.Status}
}
func (s *Store) ApplyMacOSInventoryControl(ctx context.Context, id, cert string, raw []byte, now time.Time) ([]byte, error) {
	return s.applyMacOSInventory(ctx, id, cert, raw, now, true)
}
func (s *Store) ApplyMacOSInventoryReport(ctx context.Context, id, cert string, raw []byte, now time.Time) ([]byte, error) {
	return s.applyMacOSInventory(ctx, id, cert, raw, now, false)
}
func (s *Store) applyMacOSInventory(ctx context.Context, id, cert string, raw []byte, now time.Time, isControl bool) ([]byte, error) {
	release, e := s.macOSInventoryAdmission(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	origin, ok := ctx.Value(macOSInventoryOriginKey{}).(string)
	if !ok || !validWindowsFullProcessesOrigin(origin, "tls") {
		return nil, enrollmentstate.ErrProof
	}
	raw = bytes.Clone(raw)
	var c macosinventorywire.Control
	var report macosinventorywire.Report
	if isControl {
		c, e = macosinventorywire.DecodeControl(raw)
	} else {
		report, e = macosinventorywire.DecodeReport(raw)
	}
	if e != nil {
		return nil, e
	}
	var out []byte
	e = s.transact(ctx, func(t *transaction) error {
		var err error
		now, err = macOSNow(ctx, now)
		if err != nil {
			return err
		}
		snap, err := s.macOSInventoryAuthority(t, id, cert, now)
		if err != nil {
			return err
		}
		if err = macOSInventoryClock(ctx, t, now); err != nil {
			return err
		}
		r, err := readMacOSInventoryRecord(ctx, t, id)
		if err != nil {
			return err
		}
		binding := macOSInventoryBinding(snap, origin)
		if r != nil && r.Origin != origin {
			return enrollmentstate.ErrProof
		}
		if isControl {
			if c.Binding != binding || c.ChangedAt.After(now) || c.ChangedAt.Unix() < snap.Activation.At {
				return enrollmentstate.ErrProof
			}
			if r == nil {
				if !c.Enabled {
					return macosinventorywire.ErrConflict
				}
				receipt, err := macosinventorywire.ReceiptFor(raw, now)
				if err != nil {
					return err
				}
				out, err = macosinventorywire.EncodeReceipt(receipt, raw)
				if err != nil {
					return err
				}
				r = &macOSInventoryRecord{Origin: origin, EnableRaw: raw, EnableReceipt: out, LastAt: now}
				cred := t.credentials[id]
				cred.MacOSInventoryInitialized = true
				t.credentials[id] = cred
			} else {
				previous := r.EnableRaw
				if len(r.DisableRaw) > 0 {
					previous = r.DisableRaw
				}
				retry, err := macosinventorywire.ValidateControlTransition(previous, raw, r.Floor)
				if err != nil {
					return err
				}
				if retry {
					if c.Enabled {
						out = bytes.Clone(r.EnableReceipt)
					} else {
						out = bytes.Clone(r.DisableReceipt)
					}
				} else {
					ack, err := macosinventorywire.DecodeReceipt(r.EnableReceipt, r.EnableRaw)
					if err != nil {
						return ErrStorage
					}
					if c.ChangedAt.Before(ack.ReceivedAt) || r.Latest != nil && c.ChangedAt.Before(r.Latest.CollectedAt) {
						return macosinventorywire.ErrConflict
					}
					receipt, err := macosinventorywire.ReceiptFor(raw, now)
					if err != nil {
						return err
					}
					out, err = macosinventorywire.EncodeReceipt(receipt, raw)
					if err != nil {
						return err
					}
					r.DisableRaw = raw
					r.DisableReceipt = out
					r.Floor = c.CaptureFloor
				}
			}
		} else {
			if report.Binding != binding {
				return enrollmentstate.ErrProof
			}
			if r == nil {
				return macosinventorywire.ErrConflict
			}
			if len(r.DisableRaw) > 0 {
				return macosinventorywire.ErrDisabled
			}
			enabled, err := macosinventorywire.DecodeControl(r.EnableRaw)
			if err != nil {
				return ErrStorage
			}
			if err = macosinventorywire.ValidateReportBinding(report, enabled); err != nil {
				return err
			}
			if err = macosinventorywire.ValidateLifetime(report, now); err != nil {
				return err
			}
			ack, err := macosinventorywire.DecodeReceipt(r.EnableReceipt, r.EnableRaw)
			if err != nil {
				return ErrStorage
			}
			if report.CollectedAt.Before(ack.ReceivedAt) {
				return macosinventorywire.ErrConflict
			}
			if report.CaptureSequence < r.Floor {
				return macosinventorywire.ErrConflict
			}
			if report.CaptureSequence == r.Floor {
				if r.Latest == nil || !bytes.Equal(r.ReportRaw, raw) {
					return macosinventorywire.ErrConflict
				}
				out = bytes.Clone(r.Latest.Receipt)
			} else {
				if r.Latest != nil && report.CollectedAt.Before(r.Latest.CollectedAt.Add(macosinventorywire.CaptureInterval)) {
					return macosinventorywire.ErrConflict
				}
				receipt, err := macosinventorywire.ReceiptFor(raw, now)
				if err != nil {
					return err
				}
				out, err = macosinventorywire.EncodeReceipt(receipt, raw)
				if err != nil {
					return err
				}
				r.Floor = report.CaptureSequence
				r.ReportRaw = raw
				r.Latest = &macOSInventoryLatest{Sequence: report.CaptureSequence, GenerationID: report.GenerationID, CollectedAt: report.CollectedAt, ExpiresAt: report.ExpiresAt, SourceQuality: report.SourceQuality, Sources: macOSInventorySourceStatuses(report), Receipt: out}
			}
		}
		r.LastAt = now
		if err = saveMacOSInventoryRecord(ctx, t, id, r); err != nil {
			return err
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			at, err := macOSNow(ctx, now)
			if err != nil {
				return err
			}
			if _, err = s.macOSInventoryAuthority(t, id, cert, at); err != nil {
				return err
			}
			if err = macOSInventoryClock(ctx, t, at); err != nil {
				return err
			}
			if !isControl {
				return macosinventorywire.ValidateLifetime(report, at)
			}
			return nil
		})
		return nil
	})
	if e != nil {
		return nil, e
	}
	if e = s.recheckMacOSInventoryRequest(ctx, id, cert, raw, now, isControl); e != nil {
		return nil, e
	}
	return bytes.Clone(out), nil
}

// RecheckMacOSInventoryControl and Report run at the final ingress output edge,
// after the response is fully encoded. They cannot refresh the committed receipt.
func (s *Store) RecheckMacOSInventoryControl(ctx context.Context, id, cert string, raw []byte, now time.Time) error {
	if _, err := macosinventorywire.DecodeControl(raw); err != nil {
		return err
	}
	return s.recheckMacOSInventoryRequest(ctx, id, cert, raw, now, true)
}
func (s *Store) RecheckMacOSInventoryReport(ctx context.Context, id, cert string, raw []byte, now time.Time) error {
	if _, err := macosinventorywire.DecodeReport(raw); err != nil {
		return err
	}
	return s.recheckMacOSInventoryRequest(ctx, id, cert, raw, now, false)
}
func (s *Store) recheckMacOSInventoryRequest(ctx context.Context, id, cert string, raw []byte, now time.Time, control bool) error {
	if s == nil || s.storeState == nil || s.config.Platform != "darwin" || s.config.Binding.Profile != "tls" || s.config.Binding.CollectionProfile != macosinventorywire.Profile {
		return enrollmentstate.ErrProof
	}
	return s.transact(ctx, func(t *transaction) error {
		at, e := macOSNow(ctx, now)
		if e != nil {
			return e
		}
		if _, e = s.macOSInventoryAuthority(t, id, cert, at); e != nil {
			return e
		}
		if e = macOSInventoryClock(ctx, t, at); e != nil {
			return e
		}
		r, e := readMacOSInventoryRecord(ctx, t, id)
		if e != nil {
			return e
		}
		if r == nil {
			return ErrStorage
		}
		if control {
			if !bytes.Equal(raw, r.EnableRaw) && !bytes.Equal(raw, r.DisableRaw) {
				return macosinventorywire.ErrConflict
			}
			if bytes.Equal(raw, r.EnableRaw) && len(r.DisableRaw) > 0 {
				return macosinventorywire.ErrDisabled
			}
		} else {
			if len(r.DisableRaw) > 0 {
				return macosinventorywire.ErrDisabled
			}
			if !bytes.Equal(raw, r.ReportRaw) {
				return macosinventorywire.ErrConflict
			}
			report, e := macosinventorywire.DecodeReport(raw)
			if e != nil {
				return e
			}
			if e = macosinventorywire.ValidateLifetime(report, at); e != nil {
				return e
			}
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			fresh, err := macOSNow(ctx, at)
			if err != nil {
				return err
			}
			if _, err = s.macOSInventoryAuthority(t, id, cert, fresh); err != nil {
				return err
			}
			if err = macOSInventoryClock(ctx, t, fresh); err != nil {
				return err
			}
			if !control {
				report, err := macosinventorywire.DecodeReport(raw)
				if err != nil {
					return err
				}
				return macosinventorywire.ValidateLifetime(report, fresh)
			}
			return nil
		})
		return nil
	})
}

// Maintenance only removes expired row payloads. Immutable control, last receipt,
// original capture metadata and floors survive. No capture or authority changes.
func (s *Store) MaintainMacOSInventory(ctx context.Context, now time.Time) error {
	release, e := s.macOSInventoryAdmission(ctx)
	if e != nil {
		return e
	}
	defer release()
	return s.transact(ctx, func(t *transaction) error {
		at, e := macOSNow(ctx, now)
		if e != nil {
			return e
		}
		if e = macOSInventoryClock(ctx, t, at); e != nil {
			return e
		}
		for id, c := range t.credentials {
			if !c.MacOSInventoryInitialized {
				continue
			}
			r, e := readMacOSInventoryRecord(ctx, t, id)
			if e != nil {
				return e
			}
			if r.Latest != nil && !at.Before(r.Latest.ExpiresAt) && len(r.ReportRaw) > 0 {
				r.ReportRaw = nil
				if e = saveMacOSInventoryRecord(ctx, t, id, r); e != nil {
					return e
				}
			}
		}
		return nil
	})
}
