package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/operational"
)

// These are generated, ordinary typed records. No OS inventory, collector,
// network, private filesystem source, or validator bypass participates.
func budgetJSONSize(t testing.TB, value any) int {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

func budgetHealthy(meta *operational.SectionMeta, count int) {
	meta.Quality = operational.Healthy
	meta.Reason = operational.ReasonNone
	meta.Complete = true
	meta.CountExact = true
	meta.ObservedCount = uint64(count)
}

func budgetSoftwareSnapshot(t testing.TB, at time.Time, target int) operational.Snapshot {
	t.Helper()
	s := operational.Empty(at, operational.ReasonNotImplemented)
	for k := range 128 {
		s.Sections.Software.Items = append(s.Sections.Software.Items, operational.Software{
			Name: fmt.Sprintf("fixture-package-%03d", k), Version: "1.0", Architecture: "amd64", Manager: "dpkg",
		})
	}
	budgetHealthy(&s.Sections.Software.Meta, len(s.Sections.Software.Items))
	remaining := target - budgetJSONSize(t, s)
	if remaining < 0 {
		t.Fatal("software target is below ordinary fixture size")
	}
	for k := range s.Sections.Software.Items {
		item := &s.Sections.Software.Items[k]
		for _, field := range []struct {
			value *string
			limit int
		}{{&item.Version, 192}, {&item.Name, 128}} {
			n := min(remaining, field.limit-len(*field.value))
			*field.value += strings.Repeat("1", n)
			remaining -= n
		}
	}
	if remaining != 0 || budgetJSONSize(t, s) != target || operational.Validate(s) != nil {
		t.Fatal("software fixture cannot reach validated byte target")
	}
	return s
}

// Six accepted generations accumulate a last-good section from each generation.
// The last snapshot is one byte below the 48KiB wire-profile ceiling. Services
// and mount labels are tuned so snapshot JSON + last-good record JSON is exactly 128KiB.
func budgetOperationalSamples(t testing.TB) []operational.Snapshot {
	t.Helper()
	samples := make([]operational.Snapshot, 6)
	for k := range samples {
		samples[k] = operational.Empty(time.Unix(testNow+10+int64(k), 0).UTC(), operational.ReasonNotImplemented)
	}
	one, hundred, percent, cpu := uint64(1), uint64(100), float64(99), float64(1)
	v := &samples[0].Sections.Volumes
	for k := range operational.VolumeLimit {
		v.Items = append(v.Items, operational.Volume{ID: fmt.Sprintf("mount_%d", k+1), MountPoint: fmt.Sprintf("/fixture/volume-%02d", k), Filesystem: "ext4", Kind: "local", TotalBytes: &hundred, AvailableBytes: &one, UsedPercent: &percent, MeasurementQuality: operational.Healthy, MeasurementReason: operational.ReasonNone})
	}
	budgetHealthy(&v.Meta, len(v.Items))
	n := &samples[1].Sections.Network
	for k := range operational.NetworkLimit {
		n.Items = append(n.Items, operational.NetworkInterface{Name: fmt.Sprintf("fixture%02d", k), State: "up", MTU: &hundred, RXBytes: &one, TXBytes: &one, RXErrors: &one, TXErrors: &one, IPv4Count: &one, IPv6Count: &one})
	}
	budgetHealthy(&n.Meta, len(n.Items))
	s := &samples[2].Sections.Services
	for k := range 64 {
		s.Items = append(s.Items, operational.Service{Name: fmt.Sprintf("fixture-%03d.service", k), LoadState: "loaded", ActiveState: "failed", SubState: "failed"})
	}
	budgetHealthy(&s.Meta, len(s.Items))
	p := &samples[3].Sections.Processes
	for k := range 32 {
		p.Items = append(p.Items, operational.Process{PID: uint64(k + 1), ParentPID: &one, Name: fmt.Sprintf("fixture-%02d", k), State: "sleeping", RSSBytes: &hundred, CPUTimeSeconds: &cpu, Threads: &one})
	}
	budgetHealthy(&p.Meta, len(p.Items))
	e := &samples[4].Sections.Events
	for k := range 32 {
		e.Items = append(e.Items, operational.Event{Source: "agent", Unit: fmt.Sprintf("fixture-%03d.service", k), Priority: 3, MessageID: fmt.Sprintf("%032x", k+1), Count: 1, FirstSeen: samples[4].CollectedAt.Add(-time.Minute), LastSeen: samples[4].CollectedAt})
	}
	budgetHealthy(&e.Meta, len(e.Items))
	samples[5] = budgetSoftwareSnapshot(t, samples[5].CollectedAt, operational.MaxSnapshotBytes-1)
	record := operationalRecord{LastGood: LastGood{Volumes: v, Network: n, Services: s, Processes: p, Events: e, Software: &samples[5].Sections.Software}}
	remaining := OperationalDeviceQuota - budgetJSONSize(t, samples[5]) - budgetJSONSize(t, record)
	if remaining < 0 {
		t.Fatal("ordinary cache exceeds target before padding")
	}
	for k := range s.Items {
		item := &s.Items[k]
		n := min(remaining, 128-len(item.Name))
		item.Name = strings.TrimSuffix(item.Name, ".service") + strings.Repeat("x", n) + ".service"
		remaining -= n
	}
	for k := range v.Items {
		item := &v.Items[k]
		n := min(remaining, 160-len(item.MountPoint))
		item.MountPoint += strings.Repeat("x", n)
		remaining -= n
	}
	if remaining != 0 || budgetJSONSize(t, samples[5])+budgetJSONSize(t, record) != OperationalDeviceQuota {
		t.Fatalf("ordinary service fixture cannot reach retained quota: remaining=%d snapshot=%d cache=%d", remaining, budgetJSONSize(t, samples[5]), budgetJSONSize(t, record))
	}
	for _, sample := range samples {
		if err := operational.Validate(sample); err != nil {
			t.Fatal("ordinary budget snapshot invalid", err)
		}
	}
	return samples
}

// Fixed-width, per-device/per-observation labels preserve the byte shape while
// ensuring transaction-local exact-frame reuse cannot collapse 25 devices into
// one synthetic byte-identical frame.
func budgetDeviceSample(sample operational.Snapshot, device int, sequence uint64) operational.Snapshot {
	sample.GenerationID = fmt.Sprintf("sample_%016x%016x", uint64(device), sequence)
	for _, meta := range []*operational.SectionMeta{
		&sample.Sections.Volumes.Meta, &sample.Sections.Network.Meta,
		&sample.Sections.Services.Meta, &sample.Sections.Processes.Meta,
		&sample.Sections.Software.Meta, &sample.Sections.Events.Meta,
	} {
		meta.GenerationID = sample.GenerationID
	}
	return sample
}

func budgetOperationalFrame(t testing.TB, sequence uint64, sample operational.Snapshot) []byte {
	t.Helper()
	var frame lanstore.Frame
	if err := json.Unmarshal(sampleFrame(t, sequence, sample.CollectedAt), &frame); err != nil {
		t.Fatal(err)
	}
	frame.SchemaVersion = lanstore.FrameOperationalVersion
	frame.Operational = &sample
	raw, err := json.Marshal(frame)
	if err != nil || len(raw) > lanstore.MaxFrameBytes {
		t.Fatal("ordinary budget frame exceeds wire bound", err)
	}
	// JSON whitespace exercises the real authenticated frame ceiling. It is
	// retained exactly, but is not included in the logical operational quota.
	raw = append(raw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
	if _, err := lanstore.ValidateFrame(raw, sample.CollectedAt); err != nil {
		t.Fatal("ordinary budget frame invalid", err)
	}
	return raw
}

type operationalBudgetFixture struct {
	store      *Store
	fixture    fixture
	identities []enrollmentstate.Snapshot
	samples    []operational.Snapshot
	frames     [][]byte
}

func populatedOperationalBudget(t testing.TB) operationalBudgetFixture {
	t.Helper()
	base := newFixture(t)
	base.config.Binding.CollectionProfile = operational.CollectionProfile
	base.challenge.CollectionProfile = operational.CollectionProfile
	base.config.RecordLimit, base.config.InvitationLimit, base.config.PendingLimit = 25, 25, 25
	out := operationalBudgetFixture{fixture: base, samples: budgetOperationalSamples(t)}
	out.store = base.open(t, filepath.Join(t.TempDir(), "private", "operational-budget.sqlite"))
	for k := 1; k <= 25; k++ {
		f := base
		f.requestOffset = k * 100
		f.challenge.InvitationID = id("invite", k)
		f.challenge.ClaimID = id("claim", k)
		f.secret = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(k + 32)}, 32))
		snapshot, intent := f.toIntent(t, out.store)
		cert := f.issue(t, intent)
		snapshot, err := out.store.CommitIssued(context.Background(), f.control(snapshot, 5), cert)
		if err != nil {
			t.Fatal(err)
		}
		c := f.control(snapshot, 6)
		snapshot, err = out.store.Activate(context.Background(), c, f.activation(t, cert, c))
		if err != nil {
			t.Fatal(err)
		}
		out.identities = append(out.identities, snapshot)
	}
	for k, sample := range out.samples {
		for device, identity := range out.identities {
			raw := budgetOperationalFrame(t, uint64(k+1), budgetDeviceSample(sample, device+1, uint64(k+1)))
			if device == len(out.identities)-1 {
				out.frames = append(out.frames, raw)
			}
			if _, err := out.store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, sample.CollectedAt); err != nil {
				t.Fatal("populate ordinary operational fixture", err)
			}
		}
	}
	return out
}

func checkOperationalBudget(t testing.TB, f operationalBudgetFixture) int {
	t.Helper()
	ctx := context.Background()
	total := 0
	err := f.store.transact(ctx, func(tx *transaction) error {
		if len(tx.credentials) != 25 || len(tx.operational) != 25 || len(tx.engine.Snapshots()) != 25 {
			t.Fatal("budget fixture must retain exactly 25 identities")
		}
		seenFrames := make(map[string]bool)
		for device, identity := range f.identities {
			stored, err := tx.engine.Get(identity.InvitationID)
			if err != nil || stored.State != enrollmentstate.Activated || stored.Binding.CollectionProfile != operational.CollectionProfile {
				t.Fatal("budget identity is not activated operational profile", err)
			}
			c := tx.credentials[identity.InvitationID]
			if seenFrames[c.Replay.PayloadHash] {
				t.Fatal("budget frames must be distinct across all 25 identities")
			}
			seenFrames[c.Replay.PayloadHash] = true
			frame, err := lanstore.ValidateFrame(c.Frame, c.Replay.ReceivedAt)
			if err != nil || frame.Operational == nil || len(c.Frame) != lanstore.MaxFrameBytes {
				t.Fatal("stored budget frame invalid", err)
			}
			record := tx.operational[identity.InvitationID]
			g := record.LastGood
			if g.Volumes == nil || g.Network == nil || g.Services == nil || g.Processes == nil || g.Events == nil || g.Software == nil {
				t.Fatal("budget fixture missing populated retained section")
			}
			metas := []operational.SectionMeta{g.Volumes.Meta, g.Network.Meta, g.Services.Meta, g.Processes.Meta, g.Events.Meta, g.Software.Meta}
			for k, meta := range metas {
				if meta.GenerationID != budgetDeviceSample(f.samples[k], device+1, uint64(k+1)).GenerationID || !meta.ObservedAt.Equal(f.samples[k].CollectedAt) || meta.ObservedCount == 0 {
					t.Fatal("mixed-generation retained provenance changed")
				}
			}
			n := budgetJSONSize(t, frame.Operational) + budgetJSONSize(t, record)
			if n != OperationalDeviceQuota {
				t.Fatalf("logical device bytes=%d, want quota=%d", n, OperationalDeviceQuota)
			}
			total += n
		}
		return nil
	})
	if err != nil || total != 25*OperationalDeviceQuota || total > OperationalGlobalQuota {
		t.Fatal("operational budget verification failed", err)
	}
	return total
}

// Keep complete canonical test-state copies rather than trusting a failed
// operation's return value. Nothing from these disposable records is logged.
type budgetStoredState struct {
	authority  []byte
	credential []byte
	retained   []byte
}

func budgetStates(t testing.TB, s *Store, ids ...string) map[string]budgetStoredState {
	t.Helper()
	out := make(map[string]budgetStoredState, len(ids))
	encode := func(value any) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal("encode disposable budget state", err)
		}
		return raw
	}
	if err := s.transact(context.Background(), func(tx *transaction) error {
		for _, id := range ids {
			snapshot, err := tx.engine.Get(id)
			if err != nil {
				return err
			}
			credential, hasCredential := tx.credentials[id]
			retained, hasRetained := tx.operational[id]
			if !hasCredential || !hasRetained {
				return ErrStorage
			}
			out[id] = budgetStoredState{encode(snapshot), encode(credential), encode(retained)}
		}
		return nil
	}); err != nil {
		t.Fatal("read disposable budget state", err)
	}
	return out
}

func assertBudgetStateUnchanged(t testing.TB, before, after budgetStoredState) {
	t.Helper()
	if !bytes.Equal(before.authority, after.authority) {
		t.Fatal("busy operation changed target enrollment authority")
	}
	if !bytes.Equal(before.credential, after.credential) {
		t.Fatal("busy operation changed target credential, frame, sequence, or receipt")
	}
	if !bytes.Equal(before.retained, after.retained) {
		t.Fatal("busy operation changed target retained cache or section provenance")
	}
}

func TestTwentyFiveOperationalRetainedBudget(t *testing.T) {
	f := populatedOperationalBudget(t)
	total := checkOperationalBudget(t, f)
	ctx := context.Background()
	last := f.identities[24]
	at := f.samples[5].CollectedAt
	t.Logf("ordinary activated operational identities=25 snapshot_bytes=%d cached_record_bytes=%d logical_device_bytes=%d logical_total_bytes=%d exact_frame_bytes=%d", budgetJSONSize(t, f.samples[5]), OperationalDeviceQuota-budgetJSONSize(t, f.samples[5]), OperationalDeviceQuota, total, len(f.frames[5]))

	t.Run("QuotaRejectionPreservesAgeAndReplay", func(t *testing.T) {
		before, err := f.store.OperationalView(ctx, last.Approval.DeviceID, at)
		if err != nil {
			t.Fatal(err)
		}
		over := budgetDeviceSample(budgetSoftwareSnapshot(t, at.Add(time.Second), operational.MaxSnapshotBytes), 25, 7)
		raw := budgetOperationalFrame(t, 7, over)
		if _, err := f.store.SaveObservation(ctx, last.InvitationID, last.Issuance.CertificateHash, raw, over.CollectedAt); !errors.Is(err, ErrStorage) {
			t.Fatal("expected logical quota rejection for valid 48KiB snapshot", err)
		}
		after, err := f.store.OperationalView(ctx, last.Approval.DeviceID, at.Add(3*time.Minute))
		if err != nil || after.Status != "stale" || after.Sequence == nil || *after.Sequence != 6 || !after.ReceivedAt.Equal(*before.ReceivedAt) || after.Snapshot.GenerationID != before.Snapshot.GenerationID || !after.Snapshot.CollectedAt.Equal(before.Snapshot.CollectedAt) {
			t.Fatal("quota rejection refreshed age or changed replay", err)
		}
		retry, err := f.store.SaveObservation(ctx, last.InvitationID, last.Issuance.CertificateHash, f.frames[5], at.Add(3*time.Minute))
		if err != nil || !retry.Duplicate || retry.Sequence != 6 || !retry.ReceivedAt.Equal(*before.ReceivedAt) || !retry.CollectedAt.Equal(before.Snapshot.CollectedAt) {
			t.Fatal("quota rejection lost exact accepted retry", err)
		}
		checkOperationalBudget(t, f)
		t.Log("validated 49152-byte snapshot would retain 131074 logical bytes; rejection retained sequence 6, receipt, collection age, and original mixed-generation cache")
	})

	t.Run("ConcurrentReadIngressRevoke", func(t *testing.T) {
		other := f.fixture.open(t, f.store.path)
		third := f.fixture.open(t, f.store.path)
		now := at.Add(time.Second)
		next := budgetDeviceSample(budgetSoftwareSnapshot(t, now, operational.MaxSnapshotBytes-1), 25, 7)
		raw := budgetOperationalFrame(t, 7, next)
		revoke := control(f.identities[23], 99999)
		revoke.Now = now.Unix()
		before := budgetStates(t, f.store, last.InvitationID, revoke.InvitationID)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var errs [3]error
		var elapsed [3]time.Duration
		for k := range 3 {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				<-start
				began := time.Now()
				switch k {
				case 0:
					_, errs[k] = f.store.OperationalView(ctx, last.Approval.DeviceID, now)
				case 1:
					_, errs[k] = other.SaveObservation(ctx, last.InvitationID, last.Issuance.CertificateHash, raw, now)
				case 2:
					_, errs[k] = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked})
				}
				elapsed[k] = time.Since(began)
			}(k)
		}
		close(start)
		wg.Wait()
		t.Logf("25 retained identities; concurrent end-to-end times including SQLite lock wait: read=%s (%v) ingress=%s (%v) revoke=%s (%v)", elapsed[0], errs[0], elapsed[1], errs[1], elapsed[2], errs[2])
		var busy []int
		names := []string{"read", "ingress", "revoke"}
		for k, err := range errs {
			if err == nil {
				continue
			}
			// Native remains strict first-attempt evidence. Under race, only
			// the exact BEGIN-time SQLite contention sentinel is permitted.
			if !operationalBudgetRace || err != ErrBusy {
				t.Fatalf("concurrent budget %s first attempt failed: %v", names[k], err)
			}
			busy = append(busy, k)
		}
		if len(busy) > 0 {
			// All contenders returned before inspection or retry. Successful
			// operations used different write targets, so each busy write's
			// full target state must still equal its pre-contention copy.
			after := budgetStates(t, f.store, last.InvitationID, revoke.InvitationID)
			if errs[1] == ErrBusy {
				assertBudgetStateUnchanged(t, before[last.InvitationID], after[last.InvitationID])
			}
			if errs[2] == ErrBusy {
				assertBudgetStateUnchanged(t, before[revoke.InvitationID], after[revoke.InvitationID])
			}
			for _, k := range busy {
				began := time.Now()
				var retryErr error
				switch k {
				case 0:
					_, retryErr = f.store.OperationalView(ctx, last.Approval.DeviceID, now)
				case 1:
					var receipt lanstore.Receipt
					receipt, retryErr = other.SaveObservation(ctx, last.InvitationID, last.Issuance.CertificateHash, raw, now)
					if retryErr == nil && (receipt.Duplicate || receipt.Sequence != 7 || !receipt.ReceivedAt.Equal(now) || !receipt.CollectedAt.Equal(now)) {
						t.Fatal("busy ingress retry did not commit the original new observation")
					}
				case 2:
					var result enrollmentstate.Snapshot
					result, retryErr = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked})
					if retryErr == nil && result.State != enrollmentstate.Revoked {
						t.Fatal("busy revocation retry did not revoke the original target")
					}
				}
				t.Logf("instrumented %s first attempt was ErrBusy; exact request retry=1 after all contenders returned: elapsed=%s result=%v", names[k], time.Since(began), retryErr)
				if retryErr != nil {
					t.Fatalf("instrumented %s failed its only retry: %v", names[k], retryErr)
				}
			}
		}
		t.Logf("concurrency result: first_attempt_successes=%d first_attempt_busy=%d explicit_retries=%d race_instrumented=%t", 3-len(busy), len(busy), len(busy), operationalBudgetRace)
		view, err := f.store.OperationalView(ctx, f.identities[23].Approval.DeviceID, now)
		if err != nil || view.Status != "revoked" {
			t.Fatal("concurrent revocation was not retained", err)
		}
		latest, err := f.store.OperationalView(ctx, last.Approval.DeviceID, now)
		if err != nil || latest.Status != "fresh" || latest.Sequence == nil || *latest.Sequence != 7 || latest.Snapshot == nil || latest.Snapshot.GenerationID != next.GenerationID {
			t.Fatal("concurrent ingress was not retained", err)
		}
	})

	t.Run("CanceledConnectionQueueWait", func(t *testing.T) {
		conn, err := f.store.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		queued, cancel := context.WithCancel(ctx)
		defer cancel()
		before := f.store.db.Stats().WaitCount
		done := make(chan error, 1)
		go func() {
			_, err := f.store.OperationalView(queued, last.Approval.DeviceID, at.Add(time.Second))
			done <- err
		}()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for f.store.db.Stats().WaitCount == before {
			select {
			case err := <-done:
				t.Fatal("read did not enter occupied connection queue", err)
			case <-deadline.C:
				t.Fatal("read failed to enter occupied connection queue")
			case <-time.After(time.Millisecond):
			}
		}
		began := time.Now()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("queued read did not return cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled read remained blocked on occupied connection")
		}
		t.Logf("canceled occupied-connection queue wait returned in %s while the connection remained held", time.Since(began))
		if len(f.store.operationalReads) != 0 {
			t.Fatal("canceled read retained its admission slot")
		}
	})
}

func BenchmarkTwentyFiveOperationalRetainedBudget(b *testing.B) {
	f := populatedOperationalBudget(b)
	total := checkOperationalBudget(b, f)
	last := f.identities[24]
	at := f.samples[5].CollectedAt
	report := func(b *testing.B) {
		b.ReportMetric(float64(total), "logical_total_bytes")
		b.ReportMetric(float64(OperationalDeviceQuota), "logical_device_bytes")
		b.ReportMetric(float64(budgetJSONSize(b, f.samples[5])), "snapshot_bytes")
		b.ReportMetric(float64(len(f.frames[5])), "frame_bytes")
	}
	b.Run("Read", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := f.store.OperationalView(context.Background(), last.Approval.DeviceID, at); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		report(b)
	})
	b.Run("IngressExactRetry", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			receipt, err := f.store.SaveObservation(context.Background(), last.InvitationID, last.Issuance.CertificateHash, f.frames[5], at)
			if err != nil || !receipt.Duplicate {
				b.Fatal("exact operational retry failed", err)
			}
		}
		b.StopTimer()
		report(b)
	})
	sequence := uint64(7)
	b.Run("IngressNewObservation", func(b *testing.B) {
		frames := make([][]byte, b.N)
		times := make([]time.Time, b.N)
		for k := range b.N {
			times[k] = at.Add(time.Duration(sequence-6+uint64(k)) * time.Second)
			frames[k] = budgetOperationalFrame(b, sequence+uint64(k), budgetDeviceSample(budgetSoftwareSnapshot(b, times[k], operational.MaxSnapshotBytes-1), 25, sequence+uint64(k)))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for k := range b.N {
			receipt, err := f.store.SaveObservation(context.Background(), last.InvitationID, last.Issuance.CertificateHash, frames[k], times[k])
			if err != nil || receipt.Duplicate {
				b.Fatal("new operational observation failed", err)
			}
		}
		b.StopTimer()
		sequence += uint64(b.N)
		report(b)
	})
}
