package managerreadiness

import (
	"errors"
	"testing"
	"time"
)

func TestWorkerRequiresSuccessfulFreshCompletion(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	var absent *Worker
	if absent.Snapshot("optional", now).State != "not_configured" {
		t.Fatal("absent worker enabled")
	}
	w := NewWorker(time.Second)
	if w.Snapshot("worker", now).State != "stopped" {
		t.Fatal("unstarted worker ready")
	}
	w.Start()
	if w.Snapshot("worker", now).State != "starting" {
		t.Fatal("running without completion ready")
	}
	w.Complete(now, errors.New("private-marker"))
	if w.Snapshot("worker", now).State != "failed" {
		t.Fatal("failure ready")
	}
	w.Complete(now.Add(time.Millisecond), nil)
	at := now.Add(time.Millisecond)
	if w.Snapshot("worker", at).State != "ready" {
		t.Fatal("successful recovery unavailable")
	}
	for _, at := range []time.Time{now, now.Add(2 * time.Second)} {
		if w.Snapshot("worker", at).State != "stale" {
			t.Fatal("future/stale completion ready")
		}
	}
	if got := w.Snapshot("worker", now.Add(2*time.Second)); got.CheckedAt == nil || !got.CheckedAt.Equal(at) {
		t.Fatal("read refreshed completion age")
	}
	w.Stop()
	w.Complete(now.Add(time.Second), nil)
	if w.Snapshot("worker", now.Add(time.Second)).State != "stopped" {
		t.Fatal("late callback restarted stopped worker")
	}
	w.Start()
	if w.Snapshot("worker", now.Add(time.Second)).State != "starting" {
		t.Fatal("restart reused prior success")
	}
}

func TestViewNeverPromotesUnknownEvidence(t *testing.T) {
	for _, state := range []string{"starting", "stopped", "unknown", "stale", "busy", "failed", "timeout", "running", ""} {
		if NewView(time.Now(), []Component{{Component: "fixture", State: state}}).Status == "ready" {
			t.Fatal("promoted", state)
		}
	}
	if NewView(time.Now(), nil).Status == "ready" {
		t.Fatal("empty view ready")
	}
	if NewView(time.Now(), []Component{{Component: "fixture", State: "ready"}, {Component: "optional", State: "not_configured"}}).Status != "ready" {
		t.Fatal("valid bounded scope unavailable")
	}
}

func TestWorkerClockRollbackDoesNotReplaceCompletion(t *testing.T) {
	now := time.Now().UTC()
	w := NewWorker(time.Minute)
	w.Start()
	w.Complete(now, nil)
	w.Complete(now.Add(-time.Second), nil)
	if v := w.Snapshot("worker", now.Add(-time.Second)); v.State != "stale" || v.CheckedAt == nil || !v.CheckedAt.Equal(now) {
		t.Fatal("clock rollback refreshed evidence", v)
	}
}
