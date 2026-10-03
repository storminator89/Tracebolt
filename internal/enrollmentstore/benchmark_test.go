package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
)

func populatedStore(t testing.TB, n int) (*Store, string) {
	s, last, _ := populatedStoreWithFrame(t, n, false)
	return s, last
}
func populatedStoreWithFrame(t testing.TB, n int, nearMaximum bool) (*Store, string, fixture) {
	t.Helper()
	base := newFixture(t)
	base.config.RecordLimit = n
	base.config.InvitationLimit = n
	base.config.PendingLimit = n
	s := base.open(t, filepath.Join(t.TempDir(), "private", "state.sqlite"))
	last := ""
	var lastFixture fixture
	for k := 1; k <= n; k++ {
		f := base
		f.requestOffset = k * 100
		f.challenge.InvitationID = id("invite", k)
		f.challenge.ClaimID = id("claim", k)
		f.secret = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(k + 32)}, 32))
		snapshot, intent := f.toIntent(t, s)
		cert := f.issue(t, intent)
		snapshot, err := s.CommitIssued(context.Background(), f.control(snapshot, 5), cert)
		if err != nil {
			t.Fatal(err)
		}
		c := f.control(snapshot, 6)
		snapshot, err = s.Activate(context.Background(), c, f.activation(t, cert, c))
		if err != nil {
			t.Fatal(err)
		}
		at := time.Unix(testNow+10, 0)
		frame := sampleFrame(t, 1, at)
		if nearMaximum {
			frame = nearMaxFrame(t, 1, at)
		}
		if _, err = s.SaveObservation(context.Background(), snapshot.InvitationID, cert.CertificateHash(), frame, at); err != nil {
			t.Fatal(err)
		}
		last = snapshot.InvitationID
		lastFixture = f
	}
	return s, last, lastFixture
}
func TestTwentyFivePopulatedRecordsRetainFrames(t *testing.T) {
	s, last := populatedStore(t, 25)
	snapshot, err := s.Get(context.Background(), last)
	if err != nil || snapshot.State != enrollmentstate.Activated {
		t.Fatal(err)
	}
	rows, err := s.LatestObservations(context.Background())
	if err != nil || len(rows) != 25 {
		t.Fatal("populated cap did not retain all latest observations")
	}
}
func BenchmarkTwentyFiveCredentialFrameTransaction(b *testing.B) {
	s, last := populatedStore(b, 25)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Get(context.Background(), last); err != nil {
			b.Fatal(err)
		}
	}
}

// nearMaxFrame fills ordinary allowed evidence fields and binary-searches the
// accepted content size for this fixed shape, with a small time-format margin.
// It stays within the real
// existing bundle/frame validators; no transport or parser bound is relaxed.
func nearMaxFrame(t testing.TB, sequence uint64, at time.Time) []byte {
	t.Helper()
	var frame lanstore.Frame
	if json.Unmarshal(sampleFrame(t, sequence, at), &frame) != nil {
		t.Fatal("fixture decode")
	}
	frame.Observation.Observation.Evidence = make([]model.Evidence, 16)
	for k := range frame.Observation.Observation.Evidence {
		frame.Observation.Observation.Evidence[k] = model.Evidence{ID: id("evidence", k+1), Title: "Bounded fixture evidence", Source: "Disposable fixture", Quality: "unknown", CollectedAt: at, Value: "fixture"}
	}
	makeRaw := func(n int) []byte {
		for k := range frame.Observation.Observation.Evidence {
			frame.Observation.Observation.Evidence[k].Detail = strings.Repeat("x", n)
		}
		raw, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	low, high := 0, 4096
	for low < high {
		mid := (low + high + 1) / 2
		if _, err := lanstore.ValidateFrame(makeRaw(mid), at); err == nil {
			low = mid
		} else {
			high = mid - 1
		}
	}
	// bundle.Encode adds its own current generation timestamp whose fractional
	// formatting length can vary; leave128bytes of observation headroom.
	if low > 8 {
		low -= 8
	}
	raw := makeRaw(low)
	if _, err := lanstore.ValidateFrame(raw, at); err != nil || len(raw) < 55<<10 {
		t.Fatal("near-maximum fixture is unexpectedly small or invalid")
	}
	// Valid JSON whitespace exercises the exact wire cap without relaxing the
	// dense observation's normal bundle/profile validation.
	raw = append(raw, bytes.Repeat([]byte(" "), lanstore.MaxFrameBytes-len(raw))...)
	if _, err := lanstore.ValidateFrame(raw, at); err != nil || len(raw) != lanstore.MaxFrameBytes {
		t.Fatal("exact wire-cap fixture invalid")
	}
	return raw
}
func BenchmarkTwentyFiveNearMaxFrameTransaction(b *testing.B) {
	s, last, _ := populatedStoreWithFrame(b, 25, true)
	b.ReportAllocs()
	frameBytes := len(nearMaxFrame(b, 1, time.Unix(testNow+10, 0)))
	b.ResetTimer()
	for range b.N {
		if _, err := s.Get(context.Background(), last); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(frameBytes), "frame_bytes")
}
func TestTwentyFiveNearMaxConcurrentTransactionWait(t *testing.T) {
	s, last, f := populatedStoreWithFrame(t, 25, true)
	other := f.open(t, s.path)
	third := f.open(t, s.path)
	ctx := context.Background()
	snapshot, err := s.Get(ctx, last)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := s.Get(ctx, id("invite", 24))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(testNow+11, 0)
	raw := nearMaxFrame(t, 2, at)
	proof := f.status(t, enrollmentcrypto.PurposeStatus, f.request(90), at.Unix())
	revoke := control(prior, 99999)
	revoke.Now = at.Unix()
	var wg sync.WaitGroup
	start := make(chan struct{})
	durations := make([]time.Duration, 3)
	errs := make([]error, 3)
	for k := range 3 {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			<-start
			began := time.Now()
			switch k {
			case 0:
				_, errs[k] = s.ReadStatus(ctx, last, proof, at)
			case 1:
				_, errs[k] = other.SaveObservation(ctx, last, snapshot.Issuance.CertificateHash, raw, at)
			case 2:
				_, errs[k] = third.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked})
			}
			durations[k] = time.Since(began)
		}(k)
	}
	close(start)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("25 records; dense accepted fixture at exact wire cap bytes=%d; concurrent end-to-end transaction times including lock wait: status=%s observation=%s revocation=%s", len(raw), durations[0], durations[1], durations[2])
}
