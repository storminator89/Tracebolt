package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/managerstatus"
)

// This is a finite real-SQLite contention regression at the unchanged pilot
// record cap, not a native collector, HTTP ingress or fleet-scale benchmark.
// All identities and primary reports come from existing synthetic fixtures.
func TestManagerStatusNearCapacityConcurrentReportsAndCachedReads(t *testing.T) {
	f, s, path, active, cert := completeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// One activated identity plus 23 canceled invitations consumes 24/25 slots.
	// Terminal verifiers are deliberately retained, not removed for the test.
	for n := 2; n <= 24; n++ {
		command := f.createCommand()
		command.InvitationID = id("invite", n)
		command.RequestID = id("request", n*100)
		command.InvitationHash = fmt.Sprintf("%064x", n)
		snapshot, err := s.CreateInvitation(ctx, command)
		if err != nil {
			t.Fatal("near-capacity fixture creation failed")
		}
		c := control(snapshot, n*100+1)
		if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: c, State: enrollmentstate.Canceled}); err != nil {
			t.Fatal("terminal fixture retention failed")
		}
	}
	monitor, err := managerstatus.New([]managerstatus.Check{{Component: managerstatus.LinuxEnrollment, Probe: s.ManagerStatus}}, nil)
	if err != nil || monitor.Refresh(ctx) != nil || !monitor.Snapshot().Ready {
		t.Fatal("near-capacity fixture not ready")
	}
	capacity := monitor.Snapshot().Components[0].Capacity
	if capacity == nil || *capacity != (managerstatus.CapacityMetrics{Used: 24, Limit: 25, Active: 1, Terminal: 23}) {
		t.Fatal("near-capacity retained counts incorrect")
	}
	const samples = 64
	at := time.Unix(testNow+10, 0).UTC()
	frames := make([][]byte, samples*2+1)
	for i := range frames {
		frames[i], _ = operationalFrame(t, uint64(i+1), at.Add(time.Duration(i)*time.Second), true)
	}
	report := func(i int) (time.Duration, error) {
		started := time.Now()
		r, err := s.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), frames[i], at.Add(time.Duration(i)*time.Second))
		if err == nil && (r.Sequence != uint64(i+1) || r.Duplicate) {
			err = fmt.Errorf("unexpected receipt")
		}
		return time.Since(started), err
	}
	baseline := make([]time.Duration, samples)
	for i := range baseline {
		if baseline[i], err = report(i); err != nil {
			t.Fatal("baseline primary report failed")
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	failures := make(chan string, 6)
	probeTimes := make([]time.Duration, samples)
	readTimes := make([][]time.Duration, 4)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := range probeTimes {
			started := time.Now()
			if monitor.Refresh(ctx) != nil {
				failures <- "bounded concurrent refresh failed"
				return
			}
			probeTimes[i] = time.Since(started)
		}
	}()
	for reader := range readTimes {
		readTimes[reader] = make([]time.Duration, samples)
		wg.Add(1)
		go func(reader int) {
			defer wg.Done()
			<-start
			for i := range readTimes[reader] {
				started := time.Now()
				raw, err := json.Marshal(monitor.Metrics())
				readTimes[reader][i] = time.Since(started)
				if err != nil || len(raw) > 16<<10 || bytes.Contains(raw, []byte(active.Approval.DeviceID)) || bytes.Contains(raw, []byte(path)) || bytes.Contains(raw, []byte(cert.CertificateHash())) {
					failures <- "cached metrics bound/privacy failed"
					return
				}
			}
		}(reader)
	}
	concurrent := make([]time.Duration, samples)
	waitsBefore := s.db.Stats().WaitCount
	close(start)
	for i := range concurrent {
		if concurrent[i], err = report(samples + i); err != nil {
			failures <- "concurrent primary report failed"
			break
		}
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if t.Failed() {
		return
	}
	if err = monitor.Refresh(ctx); err != nil || !monitor.Snapshot().Ready {
		t.Fatal("monitor failed to recover after concurrent reports")
	}
	// A read-only refresh must leave the exact ledger/credential bytes untouched.
	readAuthority := func() (ledger, credential []byte) {
		t.Helper()
		if s.db.QueryRowContext(ctx, "SELECT ledger FROM enrollment_state WHERE id=1").Scan(&ledger) != nil || s.db.QueryRowContext(ctx, "SELECT body FROM enrollment_credentials WHERE invitation_id=?", active.InvitationID).Scan(&credential) != nil {
			t.Fatal("fixture authority read failed")
		}
		return
	}
	ledgerBefore, credentialBefore := readAuthority()
	if monitor.Refresh(ctx) != nil {
		t.Fatal("final read-only refresh failed")
	}
	ledgerAfter, credentialAfter := readAuthority()
	if !bytes.Equal(ledgerBefore, ledgerAfter) || !bytes.Equal(credentialBefore, credentialAfter) {
		t.Fatal("diagnostics changed authority or replay floor")
	}
	// Capture the original pool before reopening; restart resets pool counters.
	loadMetrics := monitor.Metrics()
	loadStorage := *loadMetrics.Snapshot.Components[0].Storage
	if loadStorage.PoolWaitCount <= waitsBefore {
		t.Fatal("fixture did not establish actual probe/report pool contention")
	}
	// Reopen retains all terminal records and the last accepted primary sequence.
	s.Close()
	s = f.open(t, path)
	result := s.ManagerStatus(ctx)
	if result.State != managerstatus.OK || result.Capacity == nil || *result.Capacity != *capacity {
		t.Fatal("restart lost retained capacity truth")
	}
	replayAt := at.Add(2 * samples * time.Second)
	replayFrame, _ := operationalFrame(t, 1, replayAt, true)
	if _, err = s.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), replayFrame, replayAt); !errors.Is(err, lanstore.ErrReplay) {
		t.Fatal("restart/probes reset the primary replay floor")
	}
	lastAt := at.Add((2*samples - 1) * time.Second)
	if receipt, err := s.SaveObservation(ctx, active.InvitationID, cert.CertificateHash(), frames[2*samples-1], replayAt); err != nil || !receipt.Duplicate || !receipt.ReceivedAt.Equal(lastAt) {
		t.Fatal("restart/probes changed the exact original receipt")
	}
	// The final record makes enrollment unready/full, without asserting that an
	// existing identity can no longer report. No record or verifier is discarded.
	command := f.createCommand()
	command.InvitationID, command.RequestID, command.InvitationHash = id("invite", 25), id("request", 2500), fmt.Sprintf("%064x", 25)
	if _, err = s.CreateInvitation(ctx, command); err != nil {
		t.Fatal("final retained slot failed")
	}
	result = s.ManagerStatus(ctx)
	if result.State != managerstatus.Full || result.Capacity.Used != 25 || result.Capacity.Terminal != 23 || result.Capacity.Active != 1 || result.Capacity.Pending != 1 {
		t.Fatal("full capacity was not diagnosable")
	}
	if _, err = report(2 * samples); err != nil {
		t.Fatal("full enrollment capacity blocked an existing primary report")
	}
	p95 := func(values []time.Duration) time.Duration {
		ordered := append([]time.Duration(nil), values...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
		return ordered[(len(ordered)*95+99)/100-1].Round(time.Microsecond)
	}
	var cached []time.Duration
	for _, values := range readTimes {
		cached = append(cached, values...)
	}
	t.Logf("synthetic %s/%s %s GOMAXPROCS=%d: retained=24/25 active=1 terminal=23 frames=%d frame_bytes=%d baseline_report_p95=%s concurrent_report_p95=%s probe_p95=%s cached_read_p95=%s cached_reads=%d load_db_bytes=%d load_wal_bytes=%d load_pool_waits=%d load_pool_wait_ms=%d concurrent_pool_waits=%d probe_outcomes=%v", runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.GOMAXPROCS(0), samples*2+1, len(frames[0]), p95(baseline), p95(concurrent), p95(probeTimes), p95(cached), len(cached), loadStorage.DatabaseBytes, loadStorage.WALBytes, loadStorage.PoolWaitCount, loadStorage.PoolWaitMilliseconds, loadStorage.PoolWaitCount-waitsBefore, loadMetrics.Probes[0].Outcomes)
}
