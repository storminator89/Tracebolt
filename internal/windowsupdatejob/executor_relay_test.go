package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
)

func requestChallenge(t *testing.T, f *workflowFixture) []byte {
	t.Helper()
	f.m.source = nil
	f.request(t)
	raw, e := f.m.ClaimReadiness(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func reopenExecutor(t *testing.T, f *workflowFixture, s *memoryStore, n ExecutorAdapter) *Executor {
	t.Helper()
	x, e := OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return x
}

func TestExecutorSignedSourceRoundTripAndExactOutbox(t *testing.T) {
	f := fixture(t)
	raw := requestChallenge(t, f)
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: Yes}}
	x, store := executorFixture(t, f, n)
	n.onInspect = func() {
		var r ExecutorRecord
		if canonical(store.files["executor.json"], &r, MaxBytes) != nil || r.ReadinessSequence != 1 || r.LatestReadiness == nil || !bytes.Equal(r.LatestReadiness.Challenge, raw) || len(r.LatestReadiness.Report) != 0 {
			t.Fatal("readiness not durably consumed before source")
		}
	}
	proof, e := x.Readiness(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	statement, e := VerifyStatement(proof, executorKey().Public().(ed25519.PublicKey))
	if e != nil || statement.Readiness.Selection != f.source.value.Selection || statement.Deadline != f.at.Unix()+120 || statement.ExpiresAt != f.at.Unix()+60 || n.installs != 0 {
		t.Fatal(statement, e)
	}
	if e = f.m.Report(context.Background(), proof); e != nil {
		t.Fatal(e)
	}
	x.Close()
	x = reopenExecutor(t, f, store, n)
	retry, e := x.Outbox(context.Background(), "readiness", f.id, actionpermit.Digest(raw))
	if e != nil || !bytes.Equal(retry, proof) {
		t.Fatal("readiness bytes changed", e)
	}
	if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrConsumed) || len(got) != 0 || n.opens != 1 {
		t.Fatal("readiness source replay", e)
	}
	n.onInspect = nil
	permit := f.approve(t)
	if _, e = f.m.Claim(context.Background(), f.id); e != nil {
		t.Fatal(e)
	}
	result, e := x.Execute(context.Background(), permit)
	if e != nil || result.Outcome != "succeeded" || n.installs != 1 {
		t.Fatal(result, e)
	}
	proof, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(permit))
	if e != nil {
		t.Fatal(e)
	}
	statement, e = VerifyStatement(proof, executorKey().Public().(ed25519.PublicKey))
	if e != nil || *statement.Result != result || statement.IssuedAt != result.CompletedAt || statement.ExpiresAt != result.CompletedAt+300 {
		t.Fatal(statement, e)
	}
	x.Close()
	x = reopenExecutor(t, f, store, n)
	retry, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(permit))
	if e != nil || !bytes.Equal(retry, proof) {
		t.Fatal("result bytes changed on restart", e)
	}
	retry[0] ^= 1
	retry, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(permit))
	if e != nil || !bytes.Equal(retry, proof) {
		t.Fatal("caller mutated saved bytes", e)
	}
	if e = f.m.Report(context.Background(), proof); e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), retry); e != nil {
		t.Fatal(e)
	}
	status, e := x.Status(context.Background())
	if e != nil || len(status.Attempts) != 1 || status.InterventionRequired || status.Attempts[0].Result.CompletedAt != result.CompletedAt || status.InstallCapacityRemaining != MaxJobs-1 {
		t.Fatal(status, e)
	}
	status.Attempts[0].Result.CompletedAt++
	status2, e := x.Status(context.Background())
	if e != nil || status2.Attempts[0].Result.CompletedAt != result.CompletedAt {
		t.Fatal("status mutated saved result", e)
	}
	encoded, _ := json.Marshal(status)
	for _, forbidden := range []string{"signature", "publicKey", "envelope\"", "challenge\""} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatal("status leaked execution material", forbidden)
		}
	}
	if got, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest([]byte("other"))); !errors.Is(e, ErrConflict) || len(got) > 0 {
		t.Fatal("wrong reference admitted", e)
	}
	if _, e = x.Execute(context.Background(), permit); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("reconciliation repeated installation", e)
	}
}

func TestExecutorReadinessSequenceHasNoInstallLifetimeCap(t *testing.T) {
	f := fixture(t)
	f.m.source = nil
	n := &nativeFixture{readiness: f.source.value}
	n.readiness.Downloaded = No
	x, store := executorFixture(t, f, n)
	var first []byte
	for i := 0; i < MaxJobs+5; i++ {
		f.id = fmt.Sprintf("update_%032x", i+1)
		raw := requestChallenge(t, f)
		if i == 0 {
			first = bytes.Clone(raw)
		}
		c, e := VerifyChallenge(raw, f.key.Public().(ed25519.PublicKey))
		if e != nil || c.Sequence != uint64(i+1) || c.IssuedAt != f.at.Unix() {
			t.Fatal("not monotonic at identical time", c, e)
		}
		report, e := x.Readiness(context.Background(), raw)
		if e != nil {
			t.Fatal(i, e)
		}
		if e = f.m.Report(context.Background(), report); e != nil {
			t.Fatal(i, e)
		}
	}
	if x.record.Sequence != 0 || len(x.record.Attempts) != 0 || x.record.ReadinessSequence != MaxJobs+5 || f.m.record.Sequence != 0 || len(f.m.record.Jobs) != 1 || len(store.files["executor.json"]) > 8192 || n.installs != 0 {
		t.Fatal("readiness grew install history or persistent capacity")
	}
	x = reopenExecutor(t, f, store, n)
	before := n.opens
	if _, e := x.Readiness(context.Background(), first); !errors.Is(e, ErrConsumed) || n.opens != before {
		t.Fatal("older challenge replayed after restart", e)
	}
}

func TestExecutorReadinessRejectsInvalidAuthorityWithoutSource(t *testing.T) {
	for _, which := range []string{"tamper", "other_binding", "expired", "revoked", "scope_disabled", "leaf_expired", "consent_expired", "future", "wrong_signer", "malformed_signer"} {
		t.Run(which, func(t *testing.T) {
			f := fixture(t)
			raw := requestChallenge(t, f)
			n := &nativeFixture{readiness: f.source.value}
			x, store := executorFixture(t, f, n)
			switch which {
			case "tamper":
				raw = append(raw, '\n')
			case "other_binding":
				c, _ := VerifyChallenge(raw, f.key.Public().(ed25519.PublicKey))
				c.Binding.GrantID = "grant_" + strings.Repeat("9", 32)
				raw, _ = SignChallenge(c, f.key)
			case "expired":
				f.at = f.at.Add(120 * time.Second)
			case "future":
				c, _ := VerifyChallenge(raw, f.key.Public().(ed25519.PublicKey))
				c.IssuedAt++
				c.Deadline++
				raw, _ = SignChallenge(c, f.key)
			case "revoked":
				f.guard.current.Revoked = true
			case "scope_disabled":
				f.guard.current.Enabled = false
			case "leaf_expired":
				f.guard.current.LeafNotAfter = f.at.Unix()
			case "consent_expired":
				f.at = time.Unix(f.consent.ExpiresAt, 0)
				f.guard.current.LeafNotAfter = f.at.Unix() + 60
			case "wrong_signer", "malformed_signer":
				key := f.key
				if which == "malformed_signer" {
					key = executorKey()
					key[63] ^= 1
				}
				if _, e := OpenExecutor(store, f.guard, n, key, func() time.Time { return f.at }); e == nil {
					t.Fatal("unpinned signer opened")
				}
				return
			}
			if got, e := x.Readiness(context.Background(), raw); e == nil || len(got) > 0 || n.opens != 0 || x.record.ReadinessSequence != 0 {
				t.Fatal("invalid request reached source", e)
			}
		})
	}
}

func TestExecutorReadinessFinalGuardAndSourceTruth(t *testing.T) {
	for _, which := range []string{"revoked", "expired", "revision", "stale", "future", "invalid_fact", "unknown"} {
		t.Run(which, func(t *testing.T) {
			f := fixture(t)
			raw := requestChallenge(t, f)
			n := &nativeFixture{readiness: f.source.value}
			x, store := executorFixture(t, f, n)
			switch which {
			case "revoked":
				n.onInspect = func() { f.guard.current.Revoked = true }
			case "expired":
				n.onInspect = func() { f.at = f.at.Add(120 * time.Second) }
			case "revision":
				n.readiness.Selection.Revision++
			case "stale":
				n.readiness.CapturedAt--
			case "future":
				n.readiness.CapturedAt++
			case "invalid_fact":
				n.readiness.Software = ""
			case "unknown":
				n.readiness.EULAAccepted = Unknown
			}
			got, e := x.Readiness(context.Background(), raw)
			if which == "unknown" {
				s, err := VerifyStatement(got, executorKey().Public().(ed25519.PublicKey))
				if e != nil || err != nil || s.Readiness.Reason() != "readiness_unknown" {
					t.Fatal("unknown did not remain unknown", e, err)
				}
			} else if e == nil || len(got) > 0 || len(x.record.LatestReadiness.Report) > 0 {
				t.Fatal("final authority/source truth bypass", e)
			}
			if x.record.ReadinessSequence != 1 || n.opens != 1 || n.installs != 0 {
				t.Fatal("readiness consume/source contract broken")
			}
			x = reopenExecutor(t, f, store, n)
			if _, e = x.Readiness(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.opens != 1 {
				t.Fatal("invalid source recaptured", e)
			}
		})
	}
}

func TestExecutorReadinessCrashCannotRecapture(t *testing.T) {
	for _, fail := range []int{1, 2} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("write_%d_committed_%v", fail, committed), func(t *testing.T) {
				f := fixture(t)
				raw := requestChallenge(t, f)
				n := &nativeFixture{readiness: f.source.value}
				x, store := executorFixture(t, f, n)
				store.fail = fail
				store.commitFailure = committed
				if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrUncertain) || len(got) > 0 {
					t.Fatal("uncertain write released proof", e)
				}
				opens := n.opens
				if _, e := x.Readiness(context.Background(), raw); e == nil || n.opens != opens {
					t.Fatal("poisoned session reused")
				}
				// If the first consume write never committed, no source was accessed.
				// Production protected storage additionally refuses its incomplete manifest.
				if fail == 1 && !committed {
					if opens != 0 {
						t.Fatal("source preceded consume")
					}
					return
				}
				store.fail = 0
				x = reopenExecutor(t, f, store, n)
				if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrConsumed) || len(got) > 0 || n.opens != opens {
					t.Fatal("crash recaptured", e)
				}
				got, e := x.Outbox(context.Background(), "readiness", f.id, actionpermit.Digest(raw))
				if fail == 2 && committed {
					if e != nil || len(got) == 0 {
						t.Fatal("exact committed report lost", e)
					}
				} else if !errors.Is(e, ErrUnavailable) || len(got) > 0 {
					t.Fatal("missing evidence regenerated", e)
				}
			})
		}
	}
}

func TestExecutorResultExpiryNeverRenewsCompletion(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	f.guard.current.LeafNotAfter = f.at.Unix() + 1000
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
	// Completion after the dispatch deadline is legitimate; it is not permission
	// to start a new operation or to refresh this timestamp after a lost reply.
	n.onInstall = func() { f.at = f.at.Add(70 * time.Second) }
	x, store := executorFixture(t, f, n)
	result, e := x.Execute(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw))
	if e != nil {
		t.Fatal(e)
	}
	s, e := VerifyStatement(proof, executorKey().Public().(ed25519.PublicKey))
	if e != nil || s.IssuedAt <= s.Deadline || s.ExpiresAt != result.CompletedAt+300 {
		t.Fatal(s, e)
	}
	f.at = time.Unix(s.ExpiresAt, 0)
	if got, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrExpired) || len(got) > 0 {
		t.Fatal("expired report delivered", e)
	}
	status, e := x.Status(context.Background())
	if e != nil || status.Attempts[0].ReportState != "expired" || status.Attempts[0].Result.CompletedAt != result.CompletedAt {
		t.Fatal(status, e)
	}
	x = reopenExecutor(t, f, store, n)
	if !bytes.Equal(x.record.Attempts[0].ResultReport, proof) {
		t.Fatal("expired bytes replaced")
	}
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("expired result retried installation", e)
	}
	f.at = f.at.Add(-time.Second)
	if _, e = x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrExpired) {
		t.Fatal("clock rollback revived report", e)
	}
}

func TestExecutorResultCrashAndMissingEvidenceFailClosed(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed_%v", committed), func(t *testing.T) {
			f := fixture(t)
			raw := f.approve(t)
			n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
			x, store := executorFixture(t, f, n)
			store.fail = 3
			store.commitFailure = committed
			if _, e := x.Execute(context.Background(), raw); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			store.fail = 0
			x = reopenExecutor(t, f, store, n)
			status, e := x.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			got, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw))
			if committed {
				if e != nil || len(got) == 0 || status.Attempts[0].Result == nil {
					t.Fatal("committed exact result unavailable", e)
				}
			} else if !errors.Is(e, ErrUnavailable) || len(got) > 0 || !status.InterventionRequired || !status.Attempts[0].Attempted || status.Attempts[0].Result != nil {
				t.Fatal("lost completion invented", status, e)
			}
			if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
				t.Fatal("repeated crashed installation", e)
			}
			if committed {
				record := x.record
				record.Attempts[0].ResultReport = nil
				store.files["executor.json"], _ = json.Marshal(record)
				if _, e = OpenExecutor(store, f.guard, n, executorKey(), func() time.Time { return f.at }); !errors.Is(e, ErrIntegrity) {
					t.Fatal("missing signed evidence adopted", e)
				}
			}
		})
	}
}

func TestExecutorStatusAndOutboxRequireCurrentAuthority(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
	x, _ := executorFixture(t, f, n)
	if _, e := x.Execute(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
	f.guard.current.Revoked = true
	if _, e := x.Status(context.Background()); !errors.Is(e, ErrAuthority) {
		t.Fatal("status bypassed revocation", e)
	}
	if got, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrAuthority) || len(got) > 0 {
		t.Fatal("outbox bypassed revocation", e)
	}
	if n.opens != 1 || n.installs != 1 {
		t.Fatal("read-only reconciliation touched source")
	}
}

// Persistence is part of the authority window; elapsed write time must not
// silently extend source access or release an already-expired readiness report.
type readinessClockStore struct {
	Storage
	writes  int
	atWrite int
	advance func()
	steps   map[int]func()
}

func (s *readinessClockStore) Write(name string, raw []byte) error {
	e := s.Storage.Write(name, raw)
	s.writes++
	if s.writes == s.atWrite {
		s.advance()
	}
	if step := s.steps[s.writes]; step != nil {
		step()
	}
	return e
}
func TestExecutorReadinessRechecksTimeAfterDurableWrites(t *testing.T) {
	for _, write := range []int{1, 2} {
		t.Run(fmt.Sprint(write), func(t *testing.T) {
			f := fixture(t)
			raw := requestChallenge(t, f)
			n := &nativeFixture{readiness: f.source.value}
			x, store := executorFixture(t, f, n)
			elapsed := 60 * time.Second
			if write == 1 {
				elapsed = 120 * time.Second
			}
			x.store = &readinessClockStore{Storage: store, atWrite: write, advance: func() { f.at = f.at.Add(elapsed) }}
			if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrExpired) || len(got) > 0 {
				t.Fatal("durable write extended authority", e)
			}
			if n.opens != write-1 || n.installs != 0 {
				t.Fatal("source escaped original time fence")
			}
			x = reopenExecutor(t, f, store, n)
			status, e := x.Status(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			want := "missing"
			if write == 2 {
				want = "expired"
			}
			if status.Readiness.ReportState != want {
				t.Fatal("saved evidence misrepresented", status.Readiness)
			}
		})
	}
}

func TestExecutorConsecutiveDurabilityDelaysCannotEscapeExpiry(t *testing.T) {
	for _, kind := range []string{"readiness_source", "readiness_report", "install_source", "result_outbox"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			origin := f.at
			f.guard.current.LeafNotAfter = origin.Unix() + 1000
			var raw []byte
			if kind == "readiness_source" || kind == "readiness_report" {
				raw = requestChallenge(t, f)
			} else {
				raw = f.approve(t)
			}
			n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
			x, store := executorFixture(t, f, n)
			steps := map[int]func(){}
			expiry := origin.Add(120 * time.Second)
			if kind == "result_outbox" {
				if _, e := x.Execute(context.Background(), raw); e != nil {
					t.Fatal(e)
				}
				f.at = origin.Add(time.Second)
				expiry = origin.Add(300 * time.Second)
				steps[1] = func() { f.at = origin.Add(2 * time.Second) }
				steps[2] = func() { f.at = expiry }
			} else if kind == "readiness_report" {
				expiry = origin.Add(60 * time.Second)
				steps[2] = func() { f.at = origin.Add(time.Second) }
				steps[3] = func() { f.at = expiry }
			} else {
				if kind == "install_source" {
					expiry = origin.Add(60 * time.Second)
				}
				steps[1] = func() { f.at = origin.Add(time.Second) }
				steps[2] = func() { f.at = expiry }
			}
			x.store = &readinessClockStore{Storage: store, steps: steps}
			switch kind {
			case "result_outbox":
				if got, e := x.Outbox(context.Background(), "result", f.id, actionpermit.Digest(raw)); !errors.Is(e, ErrExpired) || len(got) > 0 {
					t.Fatal("post-write expired result released", e)
				}
				if n.installs != 1 {
					t.Fatal("outbox repeated native work")
				}
			case "install_source":
				r, e := x.Execute(context.Background(), raw)
				if e != nil || r.Outcome != "not_attempted" || n.opens != 0 || n.installs != 0 {
					t.Fatal("expired consumed permit reached source", r, e)
				}
			default:
				if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrExpired) || len(got) > 0 {
					t.Fatal("post-write readiness expiry bypass", e)
				}
				want := 0
				if kind == "readiness_report" {
					want = 1
				}
				if n.opens != want || n.installs != 0 {
					t.Fatal("source escaped deadline")
				}
			}
			if x.record.ClockFloor < expiry.Unix() {
				t.Fatal("fresh rejection time not durable")
			}
			f.at = expiry.Add(-time.Second)
			x = reopenExecutor(t, f, store, n)
			if _, e := x.Status(context.Background()); !errors.Is(e, ErrExpired) {
				t.Fatal("restart rollback revived expired authority", e)
			}
		})
	}
}

func TestExecutorCaptureMustFollowFreshPreSourceCheck(t *testing.T) {
	for _, kind := range []string{"readiness", "install"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			var raw []byte
			if kind == "readiness" {
				raw = requestChallenge(t, f)
			} else {
				raw = f.approve(t)
			}
			n := &nativeFixture{readiness: f.source.value}
			x, store := executorFixture(t, f, n)
			x.store = &readinessClockStore{Storage: store, atWrite: 1, advance: func() { f.at = f.at.Add(time.Second) }}
			if kind == "readiness" {
				if got, e := x.Readiness(context.Background(), raw); !errors.Is(e, ErrInvalid) || len(got) > 0 {
					t.Fatal("capture preceding source admitted", e)
				}
			} else {
				r, e := x.Execute(context.Background(), raw)
				if e != nil || r.Outcome != "not_attempted" {
					t.Fatal("install used pre-source capture", r, e)
				}
			}
			if n.opens != 1 || n.installs != 0 {
				t.Fatal("freshness failure reached installation")
			}
		})
	}
}
