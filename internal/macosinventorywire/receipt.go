package macosinventorywire

import "time"

// ReceiptFor computes receipt content only. It cannot authenticate, commit or
// prove admission. Only a future independently authenticated durable transaction
// may publish it; exact retries must use the stored original ReceivedAt/bytes.
func ReceiptFor(request []byte, receivedAt time.Time) (Receipt, error) {
	if len(request) > MaxReportBytes {
		return Receipt{}, ErrBounds
	}
	if !validTime(receivedAt) {
		return Receipt{}, ErrInvalid
	}
	r := Receipt{SchemaVersion: ReceiptVersion, RequestSHA256: requestDigest(request), ReceivedAt: receivedAt}
	if report, err := DecodeReport(request); err == nil {
		if err := ValidateLifetime(report, receivedAt); err != nil {
			return Receipt{}, err
		}
		r.Kind, r.Status = "report", "recorded"
		r.Binding, r.GrantID, r.GrantRevision, r.ControlRevision = report.Binding, report.GrantID, report.GrantRevision, report.ControlRevision
		r.CaptureFloor, r.GenerationID, r.CollectedAt, r.SnapshotSHA256 = report.CaptureSequence, report.GenerationID, &report.CollectedAt, report.SnapshotSHA256
		return r, nil
	}
	control, err := DecodeControl(request)
	if err != nil || receivedAt.Before(control.ChangedAt) {
		return Receipt{}, ErrInvalid
	}
	r.Kind, r.Status = "control", "disabled"
	if control.Enabled {
		r.Status = "enabled"
	}
	r.Binding, r.GrantID, r.GrantRevision, r.ControlRevision, r.CaptureFloor = control.Binding, control.GrantID, control.GrantRevision, control.ControlRevision, control.CaptureFloor
	return r, nil
}
func EncodeReceipt(r Receipt, request []byte) ([]byte, error) {
	if err := ValidateReceipt(r, request); err != nil {
		return nil, err
	}
	return encode(r, MaxReceiptBytes)
}
func DecodeReceipt(raw, request []byte) (Receipt, error) {
	var r Receipt
	if err := canonical(raw, MaxReceiptBytes, &r); err != nil {
		return Receipt{}, err
	}
	if err := ValidateReceipt(r, request); err != nil {
		return Receipt{}, err
	}
	return r, nil
}
func ValidateReceipt(r Receipt, request []byte) error {
	want, err := ReceiptFor(request, r.ReceivedAt)
	if err != nil {
		return err
	}
	// Compare bounded expected fields before encoding any caller-controlled text.
	// Pointer equality is not capture-time equality; only original UTC is valid.
	if (r.CollectedAt == nil) != (want.CollectedAt == nil) {
		return ErrInvalid
	}
	if r.CollectedAt != nil && (!validTime(*r.CollectedAt) || !r.CollectedAt.Equal(*want.CollectedAt)) {
		return ErrInvalid
	}
	r.CollectedAt, want.CollectedAt = nil, nil
	if r != want {
		return ErrInvalid
	}
	return nil
}
