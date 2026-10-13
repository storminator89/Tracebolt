package windowsmutationfence_test

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/actionpermit"
	wua "localrmm/internal/windowsupdatejob"
	"testing"
)

func (i *inertWUA) PrepareDownloadExact(ctx context.Context, s wua.Selection) (wua.PreparedDownload, error) {
	p, e := i.PrepareExact(ctx, s)
	if e != nil {
		return nil, e
	}
	return p.(*inertWUA), nil
}
func (i *inertWUA) DownloadOnce(ctx context.Context) (wua.NativeResult, error) {
	r := wua.NativeResult{Download: true, RebootRequired: wua.Unknown, DownloadedAfter: wua.Unknown}
	if e := wua.CheckDownloadStart(ctx, i.now()); e != nil {
		return r, e
	}
	if i.beforeStart != nil {
		i.beforeStart()
	}
	if !i.skipFinalGate {
		if e := wua.CheckNativeDownloadStart(ctx, i.now()); e != nil {
			return r, e
		}
	}
	i.calls.Add(1)
	if i.entered != nil {
		close(i.entered)
	}
	if i.release != nil {
		<-i.release
	}
	if i.downloadResult != nil {
		return *i.downloadResult, i.downloadError
	}
	r.NativeReturned = true
	r.AggregateResultKnown = true
	r.AggregateHResultKnown = true
	r.UpdateResultKnown = true
	r.UpdateHResultKnown = true
	r.AggregateOperationResult = 2
	r.OperationResult = 2
	r.DownloadedAfter = wua.Yes
	return r, i.downloadError
}
func downloadPair(t *testing.T) *pairedDomains {
	return newPair(t, true, true, false, false, true, true)
}
func setDownloadReadiness(f *pairedDomains) {
	r := &f.wuaNative.readiness
	r.Purpose = wua.DownloadPurpose
	r.Downloaded = wua.No
	r.DownloadMetadataKnown = true
	r.DownloadOrigins = "https://download.example.test"
	r.DownloadMinBytes = 10
	r.DownloadMaxBytes = 20
	r.DownloadSource = "default"
}
func TestDownloadRetirementRequiresFreshIndependentInstallation(t *testing.T) {
	f := downloadPair(t)
	ctx := context.Background()
	initialConsent := objectDigest(f.consent)
	r, e := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := wua.EncodeRecord(r)
	store := &reusableWUAHandshakeStore{raw: raw, f: f}
	actor, device := id("operator_", 10), f.consent.Binding.DeviceID
	manager, e := wua.OpenTransactional(ctx, store, f.consent.Binding, f.wuaKey, f.now)
	if e != nil {
		t.Fatal(e)
	}
	defer manager.Close()
	manager.ConfigureOperatorPolicy(func(string) bool { return true })
	manager.ConfigureDownloadPolicy(func(string) bool { return true })
	installReadiness := f.wuaNative.readiness
	setDownloadReadiness(f)
	var downloadPermit, downloadProof []byte
	for n := uint64(1); n <= 2; n++ {
		job := id("update_", 4000+int(n))
		download := n == 1
		if download {
			e = manager.RequestDownload(ctx, device, actor, job, f.wuaNative.readiness.Selection)
		} else {
			e = manager.Request(ctx, device, actor, job, f.wuaNative.readiness.Selection)
		}
		if e != nil {
			t.Fatal("fresh request", n, e)
		}
		challenge, err := manager.ClaimReadiness(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := f.executor.Readiness(ctx, challenge)
		if err != nil {
			t.Fatal("readiness", n, err)
		}
		status, err := f.executor.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if e = manager.Report(ctx, status.MutationReport); e != nil {
			t.Fatal(e)
		}
		if e = manager.Report(ctx, proof); e != nil {
			t.Fatal(e)
		}
		view, err := manager.View(ctx, device, actor)
		if err != nil || view.Job == nil || view.Job.Preview == nil {
			t.Fatal("preview", n, err)
		}
		if download {
			if manager.Approve(ctx, device, actor, job, view.Job.Preview.Digest, true) == nil {
				t.Fatal("install authority reused for download")
			}
			e = manager.ApproveDownload(ctx, device, actor, job, view.Job.Preview.Digest, true)
		} else {
			e = manager.Approve(ctx, device, actor, job, view.Job.Preview.Digest, true)
		}
		if e != nil {
			t.Fatal("approve", n, e)
		}
		var permit []byte
		if download {
			permit, e = manager.ClaimDownload(ctx, job)
		} else {
			permit, e = manager.Claim(ctx, job)
		}
		if e != nil {
			t.Fatal(e)
		}
		p, e := wua.Verify(permit, public(f.wuaKey))
		if e != nil || p.Sequence != n || p.Download() != download {
			t.Fatal("sequence/purpose", n, e)
		}
		result, err := f.executor.Execute(ctx, permit)
		if err != nil || result.Outcome != "succeeded" {
			t.Fatal("execute", n, result, err)
		}
		proof, err = f.executor.Outbox(ctx, "result", job, actionpermit.Digest(permit))
		if err != nil {
			t.Fatal(err)
		}
		if e = manager.Report(ctx, proof); e != nil {
			t.Fatal(e)
		}
		if download {
			downloadPermit, downloadProof = bytes.Clone(permit), bytes.Clone(proof)
			if result.Purpose != wua.DownloadPurpose || !result.NativeReturned || !result.CleanupSucceeded || result.DownloadedAfter != wua.Yes || result.RebootRequired != wua.Unknown {
				t.Fatal("download truth", result)
			}
			if manager.Request(ctx, device, actor, id("update_", 4999), installReadiness.Selection) == nil {
				t.Fatal("unretired download admitted install")
			}
			if manager.Retire(ctx, device, actor, job, n, actionpermit.Digest(permit), actionpermit.Digest(proof), true) == nil {
				t.Fatal("install capability retired download")
			}
			e = manager.RetireDownload(ctx, device, actor, job, n, actionpermit.Digest(permit), actionpermit.Digest(proof), true)
		} else {
			e = manager.Retire(ctx, device, actor, job, n, actionpermit.Digest(permit), actionpermit.Digest(proof), true)
		}
		if e != nil {
			t.Fatal("retire", e)
		}
		q, err := manager.ClaimRetirement(ctx, job)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := f.executor.Retire(ctx, q)
		if err != nil {
			t.Fatal("endpoint retirement", err)
		}
		if e = manager.Report(ctx, ack); e != nil {
			t.Fatal(e)
		}
		restartReusableWUA(t, f)
		f.at.Add(1)
		f.wuaNative.readiness = installReadiness
	}
	if _, e = f.executor.Accept(ctx, downloadPermit); e == nil {
		t.Fatal("retired download replayed")
	}
	if e = manager.Report(ctx, downloadProof); e == nil {
		t.Fatal("retired download report substituted for install")
	}
	saved := readWUA(t, f.wuaStore)
	if saved.Sequence != 2 || saved.Reusable.RetiredFloor != 2 || len(saved.Attempts) != 0 || objectDigest(f.consent) != initialConsent || f.wuaNative.calls.Load() != 2 {
		t.Fatal("independent stages/floors lost")
	}
	if s := f.fenceStatus(t); s.Blocked || s.Phase != "idle" {
		t.Fatal("successful retirement stranded shared owner", s)
	}
}
func TestDownloadFinalFenceAndCleanupFailureRetainOwner(t *testing.T) {
	for _, kind := range []string{"expiry", "revocation", "cleanup", "no_native_hook", "partial", "cancel", "result_write"} {
		t.Run(kind, func(t *testing.T) {
			f := downloadPair(t)
			setDownloadReadiness(f)
			// Produce the exact signed download preview through the real manager seam.
			r, _ := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.now().Unix())
			raw, _ := wua.EncodeRecord(r)
			c := f.wuaStore.files["receipt.json"]
			store := &domainStore{files: map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}}
			m, e := wua.Open(store, f.wuaAuthority, readySource{f.wuaNative.readiness}, f.wuaKey, f.now)
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			id := id("update_", 5001)
			operator := "operator_0000000000000000000000000000000a"
			if e = m.RequestDownload(context.Background(), f.consent.Binding.DeviceID, operator, id, f.wuaNative.readiness.Selection); e != nil {
				t.Fatal(e)
			}
			rec, _ := wua.DecodeRecord(store.files["jobs.json"])
			ch, _ := wua.VerifyChallenge(rec.Jobs[0].Challenge, public(f.wuaKey))
			s, _ := f.wuaSession.Status(context.Background())
			proof, _ := wua.SignStatement(wua.Statement{Version: wua.RelayVersion, Kind: "mutation", Binding: f.consent.Binding, JobID: id, ReferenceDigest: actionpermit.Digest(rec.Jobs[0].Challenge), Deadline: ch.Deadline, IssuedAt: f.now().Unix(), ExpiresAt: f.now().Unix() + 60, Mutation: &s}, f.wuaExecutorKey)
			if e = m.Report(context.Background(), proof); e != nil {
				t.Fatal(e)
			}
			if e = m.ApproveDownload(context.Background(), f.consent.Binding.DeviceID, operator, id, rec.Jobs[0].Preview.Digest, true); e != nil {
				t.Fatal(e)
			}
			permit, e := m.ClaimDownload(context.Background(), id)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "expiry":
				f.wuaNative.beforeStart = func() { f.at.Add(60) }
			case "revocation":
				f.wuaNative.beforeStart = func() { f.wuaAuthority.value.Enabled = false }
			case "cleanup":
				f.wuaNative.closeError = wua.ErrUncertain
			case "no_native_hook":
				f.wuaNative.skipFinalGate = true
			case "partial":
				f.wuaNative.downloadResult = &wua.NativeResult{Download: true, NativeReturned: true, AggregateResultKnown: true, AggregateHResultKnown: true, UpdateResultKnown: true, UpdateHResultKnown: true, AggregateOperationResult: 3, AggregateHResult: -1, OperationResult: 2, HResult: 0, DownloadedAfter: wua.Yes, RebootRequired: wua.Unknown}
			case "cancel":
				f.wuaNative.downloadError = context.Canceled
			case "result_write":
				f.wuaStore.before = func(name string, b []byte) error {
					var r wua.ExecutorRecord
					if name == "executor.json" && json.Unmarshal(b, &r) == nil && len(r.Attempts) == 1 && r.Attempts[0].Result != nil {
						return wua.ErrUncertain
					}
					return nil
				}
			}
			result, e := f.executor.Execute(context.Background(), permit)
			if kind == "no_native_hook" || kind == "result_write" {
				if e == nil {
					t.Fatal("native admission missing produced releasable receipt")
				}
			} else if e != nil || result.Outcome != "uncertain" {
				t.Fatal("lost uncertain truth", result, e)
			}
			if !f.fenceStatus(t).Blocked {
				t.Fatal("uncertainty unlocked shared owner")
			}
			if kind == "expiry" || kind == "revocation" {
				if f.wuaNative.calls.Load() != 0 {
					t.Fatal("late native download")
				}
			}
			if kind == "partial" && (result.AggregateOperationResult != 3 || result.AggregateHResult != -1 || result.OperationResult != 2 || result.DownloadedAfter != wua.Yes) {
				t.Fatal("partial result erased", result)
			}
			if kind == "cancel" && (!result.NativeReturned || result.DownloadedAfter != wua.Yes) {
				t.Fatal("cancellation erased actual returned content", result)
			}
			if kind == "cleanup" && (!result.NativeReturned || result.CleanupSucceeded || result.DownloadedAfter != wua.Yes) {
				t.Fatal("cleanup lost cached-content/native-return truth", result)
			}
			f.at.Add(3600)
			if !f.fenceStatus(t).Blocked {
				t.Fatal("elapsed unlock")
			}
		})
	}
}
