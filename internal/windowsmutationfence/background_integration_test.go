package windowsmutationfence_test

import (
	"context"
	"errors"
	fence "localrmm/internal/windowsmutationfence"
	wua "localrmm/internal/windowsupdatejob"
	"testing"
)

func TestBackgroundKernelDurableResultRestartAndUncertainStop(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "settled", true: "uncertain-cleanup"}[uncertain], func(t *testing.T) {
			f := newPair(t, true, true)
			if f.shared.Roster.Version != fence.BackgroundRosterVersion || f.consent.ScheduleAcknowledged {
				t.Fatal("wrong profile")
			}
			if uncertain {
				f.wuaNative.closeError = errors.New("native cleanup still incomplete")
			}
			result, e := f.executor.Execute(context.Background(), f.wuaPermit)
			if e != nil {
				t.Fatal(e)
			}
			if !result.Attempted || f.wuaNative.calls.Load() != 1 {
				t.Fatal("not exactly once")
			}
			raw, _ := f.wuaStore.Read("executor.json")
			f.executor.Close()
			f.openWUA(t)
			if _, e = f.executor.Execute(context.Background(), f.wuaPermit); !errors.Is(e, wua.ErrConsumed) {
				t.Fatal("restarted runnable capability", e)
			}
			saved, _ := f.wuaStore.Read("executor.json")
			if string(saved) != string(raw) {
				t.Fatal("replay changed original outcome")
			}
			status := f.fenceStatus(t)
			if status.Blocked != uncertain {
				t.Fatal("uncertainty/release mismatch", status)
			}
			if uncertain && result.Outcome != "uncertain" {
				t.Fatal(result)
			}
		})
	}
}
func TestBackgroundMSIAndWUAUseOneSharedOwner(t *testing.T) {
	f := newPair(t, true, true)
	entered, release := make(chan struct{}), make(chan struct{})
	f.msiNative.entered = entered
	f.msiNative.release = release
	if e := f.endpoint.Accept(context.Background(), f.msiPermit); e != nil {
		t.Fatal(e)
	}
	await(t, entered)
	r, e := f.executor.Execute(context.Background(), f.wuaPermit)
	close(release)
	f.endpoint.Wait()
	if e != nil || r.Attempted || r.Outcome != "not_attempted" || f.wuaNative.calls.Load() != 0 {
		t.Fatal("overlapping native authority", r, e)
	}
}
