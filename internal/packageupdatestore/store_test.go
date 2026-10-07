//go:build linux

package packageupdatestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"localrmm/internal/actionpermit"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
)

var ctx = context.Background()

const now int64 = 1700000000
const actor = "operator_11111111111111111111111111111111"

func fixtureRecord(t *testing.T) (packageupdate.Record, packageupdate.PrepareRequest, packageupdate.Preview) {
	t.Helper()
	raw, err := os.ReadFile("../packageplan/testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := packageplan.Decode(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	b := packageupdate.Binding{ManagerID: "manager_11111111111111111111111111111111", DeviceID: plan.EndpointID, IncarnationDigest: plan.IncarnationDigest, RootPolicyDigest: plan.RootPolicyDigest, TransportProfile: "production-tls"}
	r, err := packageupdate.New(b, now)
	if err != nil {
		t.Fatal(err)
	}
	req := packageupdate.PrepareRequest{RequestID: "update_11111111111111111111111111111111", Packages: []packageupdate.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	preview, err := packageupdate.DescribePreview(ctx, b, req, actor, plan, []packageupdate.Source{{IdentityDigest: plan.Packages[0].Archive.SourceIdentityDigest, Label: "Synthetic repository", Suite: "trixie", Component: "main"}})
	if err != nil {
		t.Fatal(err)
	}
	return r, req, preview
}
func fixture(t *testing.T) (*Store, string, packageupdate.Record, packageupdate.PrepareRequest, packageupdate.Preview) {
	t.Helper()
	r, req, p := fixtureRecord(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "updates.sqlite")
	s, err := Create(ctx, path, r.Binding, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path, r, req, p
}
func encode(t *testing.T, r packageupdate.Record) []byte {
	t.Helper()
	raw, err := packageupdate.Encode(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func clone(t *testing.T, r packageupdate.Record) packageupdate.Record {
	t.Helper()
	out, err := packageupdate.Decode(ctx, encode(t, r))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func save(t *testing.T, s *Store, old, next packageupdate.Record) {
	t.Helper()
	if err := s.CompareAndSwap(ctx, old.Binding, old.Revision, encode(t, next)); err != nil {
		t.Fatal(err)
	}
	assertRecord(t, s, next)
}
func assertRecord(t *testing.T, s *Store, want packageupdate.Record) {
	t.Helper()
	raw, err := s.Open(ctx, want.Binding)
	if err != nil || !bytes.Equal(raw, encode(t, want)) {
		t.Fatalf("record mismatch: %v", err)
	}
}
func prepare(t *testing.T, s *Store, r packageupdate.Record, req packageupdate.PrepareRequest) packageupdate.Record {
	t.Helper()
	next, err := packageupdate.Prepare(ctx, r, req, actor, r.ClockFloor)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	return next
}
func approved(t *testing.T) (*Store, string, packageupdate.Record, packageupdate.Preview) {
	t.Helper()
	s, path, r, req, p := fixture(t)
	r = prepare(t, s, r, req)
	next, err := packageupdate.AttachPreview(ctx, r, p, now+1)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	r = next
	next, err = packageupdate.Approve(ctx, r, packageupdate.ApprovalRequest{RequestID: p.RequestID, PreviewDigest: p.Digest}, actor, now+2)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	return s, path, next, p
}
func TestCreateCanonicalCASAndCleanReopen(t *testing.T) {
	s, path, r, req, _ := fixture(t)
	assertRecord(t, s, r)
	raw, err := s.Open(ctx, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	assertRecord(t, s, r)
	r = prepare(t, s, r, req)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(ctx, path, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertRecord(t, reopened, r)
	if _, err = Create(ctx, path, r.Binding, now); err == nil {
		t.Fatal("adopted existing used state")
	}
}
func TestConcurrentCASHasOneWinnerAndConflictsAreClean(t *testing.T) {
	s, path, r, req, _ := fixture(t)
	next, err := packageupdate.Prepare(ctx, r, req, actor, now)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, next)
	copyStore := *s
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := copyStore.CompareAndSwap(ctx, r.Binding, r.Revision, raw)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, packageupdate.ErrConflict) {
				t.Errorf("CAS: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("CAS winners", winners.Load())
	}
	assertRecord(t, s, next)
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, raw); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("stale revision accepted", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExisting(ctx, path, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertRecord(t, reopened, next)
}
func TestExactBindingAcrossOpenAndCAS(t *testing.T) {
	changes := map[string]func(*packageupdate.Binding){
		"manager":     func(b *packageupdate.Binding) { b.ManagerID = "manager_22222222222222222222222222222222" },
		"device":      func(b *packageupdate.Binding) { b.DeviceID = "agent_22222222222222222222222222222222" },
		"incarnation": func(b *packageupdate.Binding) { b.IncarnationDigest = actionpermit.Digest([]byte("other-incarnation")) },
		"root-policy": func(b *packageupdate.Binding) { b.RootPolicyDigest = actionpermit.Digest([]byte("other-policy")) },
		"transport":   func(b *packageupdate.Binding) { b.TransportProfile = "disposable-http-test" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s, path, r, _, _ := fixture(t)
			b := r.Binding
			change(&b)
			if _, err := s.Open(ctx, b); !errors.Is(err, packageupdate.ErrConflict) {
				t.Fatal("unbound Open", err)
			}
			next := clone(t, r)
			next.Revision++
			next.Binding = b
			if err := s.CompareAndSwap(ctx, b, r.Revision, encode(t, next)); !errors.Is(err, packageupdate.ErrConflict) {
				t.Fatal("unbound CAS", err)
			}
			if err := s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, next)); !errors.Is(err, packageupdate.ErrConflict) {
				t.Fatal("unbound record", err)
			}
			assertRecord(t, s, r)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if other, err := OpenExisting(ctx, path, b); err == nil {
				other.Close()
				t.Fatal("adopted new binding")
			}
			good, err := OpenExisting(ctx, path, r.Binding)
			if err != nil {
				t.Fatal("bad binding changed store", err)
			}
			defer good.Close()
			assertRecord(t, good, r)
		})
	}
}
func TestRejectHistoryMutationAndRollbackWithoutPoison(t *testing.T) {
	s, _, r, p := approved(t)
	changes := map[string]func(*packageupdate.Record){
		"revision":          func(n *packageupdate.Record) { n.Revision = r.Revision },
		"revision-skip":     func(n *packageupdate.Record) { n.Revision++ },
		"clock-rollback":    func(n *packageupdate.Record) { n.ClockFloor = r.ClockFloor - 1 },
		"drop-job":          func(n *packageupdate.Record) { n.Jobs = []packageupdate.Job{} },
		"approval-change":   func(n *packageupdate.Record) { n.Jobs[0].ApprovedAt-- },
		"created-change":    func(n *packageupdate.Record) { n.Jobs[0].CreatedAt-- },
		"approved-to-ready": func(n *packageupdate.Record) { n.Jobs[0].ApprovedAt = 0; n.Jobs[0].State = packageupdate.PreviewReady },
		"preview-change": func(n *packageupdate.Record) {
			sources := append([]packageupdate.Source(nil), p.Sources...)
			sources[0].Label = "Changed description"
			v, err := packageupdate.DescribePreview(ctx, n.Binding, n.Jobs[0].Request, n.Jobs[0].ActorID, p.Plan, sources)
			if err != nil {
				t.Fatal(err)
			}
			n.Jobs[0].Preview = &v
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			n := clone(t, r)
			n.Revision++
			n.ClockFloor = now + 3
			change(&n)
			raw, err := json.Marshal(n)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, raw); err == nil {
				t.Fatal("accepted history mutation")
			}
			assertRecord(t, s, r)
		})
	}
	next, err := packageupdate.ClaimForFixture(ctx, r, p.RequestID, p.Digest, now+3)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	r = next
	for _, change := range []func(*packageupdate.Record){func(n *packageupdate.Record) { n.Jobs[0].ClaimedAt++ }, func(n *packageupdate.Record) { n.Jobs[0].ClaimedAt = 0; n.Jobs[0].State = packageupdate.Approved }} {
		n := clone(t, r)
		n.Revision++
		n.ClockFloor = now + 5
		n.Jobs[0].UpdatedAt = now + 5
		change(&n)
		if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, n)); err == nil {
			t.Fatal("rewrote claim")
		}
		assertRecord(t, s, r)
	}
	next, err = packageupdate.Revoke(ctx, r, now+6)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	r = next
	n := clone(t, r)
	n.Revision++
	n.ClockFloor++
	n.RevokedAt = 0
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, n)); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("removed revocation", err)
	}
	assertRecord(t, s, r)
}
func TestPrepareIntentImmutableAndCapacityRetained(t *testing.T) {
	s, path, r, req, _ := fixture(t)
	r = prepare(t, s, r, req)
	for _, change := range []func(*packageupdate.Job){func(j *packageupdate.Job) { j.Request.Packages[0].Name = "other-package" }, func(j *packageupdate.Job) { j.ActorID = "operator_22222222222222222222222222222222" }, func(j *packageupdate.Job) { j.Request.RequestID = "update_22222222222222222222222222222222" }} {
		n := clone(t, r)
		n.Revision++
		change(&n.Jobs[0])
		if err := s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, n)); !errors.Is(err, packageupdate.ErrConflict) {
			t.Fatal("changed intent", err)
		}
	}
	for i := 1; i <= packageupdate.MaxJobs; i++ {
		next, err := packageupdate.FailPreparation(ctx, r, r.Jobs[len(r.Jobs)-1].Request.RequestID, r.ClockFloor+1)
		if err != nil {
			t.Fatal(err)
		}
		save(t, s, r, next)
		r = next
		if i < packageupdate.MaxJobs {
			req.RequestID = fmt.Sprintf("update_%032x", i+1)
			r = prepare(t, s, r, req)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := OpenExisting(ctx, path, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertRecord(t, s, r)
	req.RequestID = "update_99999999999999999999999999999999"
	if _, err = packageupdate.Prepare(ctx, r, req, actor, r.ClockFloor+1); !errors.Is(err, packageupdate.ErrCapacity) {
		t.Fatal("lost capacity floor", err)
	}
	n := clone(t, r)
	n.Revision++
	n.Jobs = n.Jobs[:len(n.Jobs)-1]
	if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, n)); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("pruned job history", err)
	}
	assertRecord(t, s, r)
}
func TestCanonicalByteAndSizeBounds(t *testing.T) {
	s, _, r, _, _ := fixture(t)
	next, err := packageupdate.Observe(ctx, r, now+1)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, next)
	for _, bad := range [][]byte{nil, append([]byte(" "), raw...), append(append([]byte(nil), raw...), byte('\n')), bytes.Repeat([]byte("x"), packageupdate.MaxRecordBytes+1), bytes.Replace(raw, []byte(`"version":`), []byte(`"unexpected":0,"version":`), 1)} {
		if err = s.CompareAndSwap(ctx, r.Binding, r.Revision, bad); err == nil {
			t.Fatal("accepted noncanonical/oversized bytes")
		}
		assertRecord(t, s, r)
	}
	save(t, s, r, next)
}

func TestUncertainCommitFencesCopiesAndReopen(t *testing.T) {
	for _, mode := range []string{"before-commit", "after-commit", "canceled-after-commit", "sqlite-write-error"} {
		t.Run(mode, func(t *testing.T) {
			s, path, r, req, _ := fixture(t)
			next, err := packageupdate.Prepare(ctx, r, req, actor, now)
			if err != nil {
				t.Fatal(err)
			}
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			calls := 0
			s.inner.commit = func(c context.Context, conn *sql.Conn) error {
				calls++
				if mode == "before-commit" {
					return errors.New("injected commit failure")
				}
				if err := commit(c, conn); err != nil {
					return err
				}
				if mode == "canceled-after-commit" {
					cancel()
					return nil
				}
				return errors.New("injected lost commit acknowledgement")
			}
			if mode == "sqlite-write-error" {
				s.inner.write = func(c context.Context, conn *sql.Conn, raw []byte) error {
					if _, err := conn.ExecContext(c, "PRAGMA query_only=ON"); err != nil {
						return err
					}
					return writeRecord(c, conn, raw)
				}
			}
			copyStore := *s
			if err = s.CompareAndSwap(callCtx, r.Binding, r.Revision, encode(t, next)); !errors.Is(err, packageupdate.ErrUncertain) {
				t.Fatal("uncertain write looked clean", err)
			}
			originalCalls := calls
			if _, err = copyStore.Open(ctx, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
				t.Fatal("copy not fenced", err)
			}
			if err = copyStore.CompareAndSwap(ctx, r.Binding, r.Revision, encode(t, next)); !errors.Is(err, packageupdate.ErrUncertain) || calls != originalCalls {
				t.Fatal("blindly retried uncertain commit", err)
			}
			if err = s.Close(); !errors.Is(err, packageupdate.ErrUncertain) {
				t.Fatal("poisoned Close cleared fence", err)
			}
			if again, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
				if again != nil {
					again.Close()
				}
				t.Fatal("uncertain store reopened", err)
			}
			if _, err = Create(ctx, path, r.Binding, now); err == nil {
				t.Fatal("uncertain store reset")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var body []byte
			var active int
			if err = db.QueryRow("SELECT record,active FROM package_update_state WHERE id=1").Scan(&body, &active); err != nil {
				t.Fatal(err)
			}
			want := r
			if mode == "after-commit" || mode == "canceled-after-commit" {
				want = next
			}
			if active != 1 || !bytes.Equal(body, encode(t, want)) {
				t.Fatal("fence or committed canonical bytes lost")
			}
		})
	}
}
func TestCanceledBeforeWriteRemainsUsable(t *testing.T) {
	s, _, r, _, _ := fixture(t)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Open(c, r.Binding); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	next, err := packageupdate.Observe(ctx, r, now+1)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompareAndSwap(c, r.Binding, r.Revision, encode(t, next)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	assertRecord(t, s, r)
	save(t, s, r, next)
}
func TestProcessCrashLeavesDurableFence(t *testing.T) {
	r, _, _ := fixtureRecord(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "crash.sqlite")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_PACKAGE_UPDATE_CRASH_FIXTURE="+path)
	out, err := cmd.CombinedOutput()
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 23 {
		t.Fatalf("crash helper: %v %s", err, out)
	}
	for range 2 {
		if s, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
			if s != nil {
				s.Close()
			}
			t.Fatal("crash adopted", err)
		}
	}
	if _, err = Create(ctx, path, r.Binding, now); err == nil {
		t.Fatal("crash reset")
	}
}
func TestCrashHelper(t *testing.T) {
	path := os.Getenv("TRACEBOLT_PACKAGE_UPDATE_CRASH_FIXTURE")
	if path == "" {
		return
	}
	r, req, _ := fixtureRecord(t)
	s, err := Create(ctx, path, r.Binding, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = prepare(t, s, r, req)
	// Intentional abrupt termination: no Store.Close and no resource cleanup.
	os.Exit(23)
}
func TestCorruptOrMissingStateNeverReinitialized(t *testing.T) {
	for _, mutation := range []string{"DELETE FROM package_update_state", "DROP TABLE package_update_state", "PRAGMA user_version=2", "CREATE TABLE unexpected(value TEXT)", "UPDATE package_update_state SET record=x'7b7d'", "ALTER TABLE package_update_state RENAME COLUMN active TO missing_guard"} {
		t.Run(strings.Fields(mutation)[0]+"-"+fmt.Sprint(len(mutation)), func(t *testing.T) {
			s, path, r, _, _ := fixture(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			db.Close()
			if bad, err := OpenExisting(ctx, path, r.Binding); err == nil {
				bad.Close()
				t.Fatal("adopted corrupt state")
			}
			if _, err = Create(ctx, path, r.Binding, now); err == nil {
				t.Fatal("reinitialized corrupt state")
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.sqlite")
	r, _, _ := fixtureRecord(t)
	if _, err := OpenExisting(ctx, path, r.Binding); err == nil {
		t.Fatal("created missing store")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("OpenExisting touched missing path")
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, path, r.Binding, now); err == nil {
		t.Fatal("adopted empty file")
	}
	if _, err := OpenExisting(ctx, path, r.Binding); err == nil {
		t.Fatal("opened empty file")
	}
}
func TestMutationOutsideStorePoisonsAndKeepsFence(t *testing.T) {
	s, path, r, _, _ := fixture(t)
	if _, err := s.inner.db.Exec("UPDATE package_update_state SET record=? WHERE id=1", encode(t, mustObserve(t, r, now+1))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("accepted changed state", err)
	}
	if err := s.Close(); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal(err)
	}
	if _, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("cleared guard on invalid state", err)
	}
}
func mustObserve(t *testing.T, r packageupdate.Record, at int64) packageupdate.Record {
	t.Helper()
	n, err := packageupdate.Observe(ctx, r, at)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUnsignedRevisionFloorSurvivesSQLite(t *testing.T) {
	s, path, r, _, _ := fixture(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Seed a high-floor synthetic fixture rather than performing 2^64 commits.
	// Production callers have no such initialization or restore API.
	r.Revision = ^uint64(0) - 1
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE package_update_state SET record=? WHERE id=1", encode(t, r)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = OpenExisting(ctx, path, r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next, err := packageupdate.Observe(ctx, r, now+1)
	if err != nil {
		t.Fatal(err)
	}
	save(t, s, r, next)
	if next.Revision != ^uint64(0) {
		t.Fatal("truncated unsigned revision")
	}
	overflow := clone(t, next)
	overflow.Revision = 1
	overflow.ClockFloor++
	if err = s.CompareAndSwap(ctx, next.Binding, next.Revision, encode(t, overflow)); !errors.Is(err, packageupdate.ErrConflict) {
		t.Fatal("accepted revision wrap/reset", err)
	}
	assertRecord(t, s, next)
}
