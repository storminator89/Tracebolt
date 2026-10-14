package macosservice

import "context"

// Uninstall is a one-attempt, exact-owned terminalization. An uncertain phase
// is read-only forever; it is not retried, rolled back or treated as absence.
// The immutable used fence, owner, phase receipts, binaries, source archive,
// dedicated account and all enrollment/sender state are retained.
func Uninstall(ctx context.Context, r InstallRequest, backend InstallBackend) (result InstallResult, resultErr error) {
	result = InstallResult{SchemaVersion: "tracebolt.macos-service-uninstall.v1", ReadOnly: !r.Apply, Status: "blocked"}
	p, err := Plan(r.Selection)
	if err != nil || ctx == nil || r.Selection.RenderOnly {
		return result, ErrRequest
	}
	if ctx.Err() != nil {
		return result, ErrPreflight
	}
	if backend == nil {
		result.Status = "unavailable"
		return result, ErrUnavailable
	}
	result.AdapterAvailable = true
	session, err := backend.Open(ctx, r.Selection, r.Apply)
	if err != nil || session == nil {
		return result, ErrPreflight
	}
	defer func() {
		if session.Close() != nil {
			result.Status = "blocked"
			resultErr = ErrPreflight
			if result.MutationAttempted {
				result.Status = "indeterminate"
				resultErr = ErrIndeterminate
			}
		}
	}()
	inspect := func() (InstallSnapshot, error) {
		if ctx.Err() != nil {
			return InstallSnapshot{}, ErrPreflight
		}
		s, e := session.Inspect(ctx)
		if e != nil || ctx.Err() != nil {
			return InstallSnapshot{}, ErrPreflight
		}
		result.ObservedPlist, result.ObservedJob = s.Plist, s.Job
		return s, nil
	}
	snapshot, err := inspect()
	if err != nil {
		return result, ErrPreflight
	}
	owner, err := ownershipFor(r.Selection, p, snapshot)
	if err != nil {
		return result, err
	}
	result.OwnershipSHA256 = owner.SHA256()
	if snapshot.Custody != Present || snapshot.Owner == nil || *snapshot.Owner != owner || len(snapshot.Receipts) != 4 || !receiptPrefix(owner, snapshot.Receipts) {
		return result, ErrCollision
	}
	last := snapshot.Receipts[3]
	result.LastReceipt = &last
	want := expectedRemovalReceipts(owner)
	if len(snapshot.RemovalReceipts) > 4 {
		return result, ErrCollision
	}
	for i, receipt := range snapshot.RemovalReceipts {
		if receipt != want[i] {
			return result, ErrCollision
		}
	}
	if n := len(snapshot.RemovalReceipts); n > 0 {
		last := snapshot.RemovalReceipts[n-1]
		result.LastRemovalReceipt = &last
		result.ReadOnly = true
		if n == 4 && runtimeMatches(snapshot, owner, Absent, Absent) {
			result.Status = "owned-removal-confirmed"
			return result, nil
		}
		result.Status = "indeterminate"
		return result, ErrIndeterminate
	}
	if !runtimeMatches(snapshot, owner, Present, Present) {
		return result, ErrCollision
	}
	result.Status = "owned-removal-ready"
	if !r.Apply {
		return result, nil
	}
	remove, ok := session.(RemovalSession)
	if !ok {
		result.Status = "unavailable"
		return result, ErrUnavailable
	}
	check := func(receipts []RemovalReceipt, plist, job Presence) bool {
		now, e := inspect()
		if e != nil || now.Custody != Present || now.Owner == nil || *now.Owner != owner || len(now.Receipts) != 4 || !receiptPrefix(owner, now.Receipts) || len(now.RemovalReceipts) != len(receipts) || !runtimeMatches(now, owner, plist, job) {
			return false
		}
		for i, r := range receipts {
			if now.RemovalReceipts[i] != r {
				return false
			}
		}
		if len(receipts) > 0 {
			last := receipts[len(receipts)-1]
			result.LastRemovalReceipt = &last
		}
		return true
	}
	if !check(nil, Present, Present) {
		result.Status = "blocked"
		return result, ErrPreflight
	}
	result.MutationAttempted = true
	result.Status = "indeterminate"
	if remove.AppendRemovalReceipt(ctx, want[0]) != nil || !check(want[:1], Present, Present) {
		return result, ErrIndeterminate
	}
	if remove.Bootout(ctx, owner) != nil || !check(want[:1], Present, Absent) {
		return result, ErrIndeterminate
	}
	if remove.AppendRemovalReceipt(ctx, want[1]) != nil || !check(want[:2], Present, Absent) {
		return result, ErrIndeterminate
	}
	if remove.AppendRemovalReceipt(ctx, want[2]) != nil || !check(want[:3], Present, Absent) {
		return result, ErrIndeterminate
	}
	if remove.RemoveOwnedPlist(ctx, owner) != nil || !check(want[:3], Absent, Absent) {
		return result, ErrIndeterminate
	}
	if remove.AppendRemovalReceipt(ctx, want[3]) != nil || !check(want, Absent, Absent) {
		return result, ErrIndeterminate
	}
	result.Status = "owned-removal-confirmed"
	return result, nil
}
