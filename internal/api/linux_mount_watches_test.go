package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/health"
	"localrmm/internal/linuxmountwatch"
	"os"
	"strings"
	"testing"
	"time"
)

type mountSourceFixture struct {
	failure error
	fixtureHealthSource
	in linuxmountwatch.Input
}

func (f *mountSourceFixture) WithLinuxMountWatch(ctx context.Context, device string, target *linuxmountwatch.Target, epoch string, fn func(linuxmountwatch.Input, func(time.Time) error) error) error {
	if f.failure != nil {
		return f.failure
	}
	if device != f.in.DeviceID {
		return linuxmountwatch.ErrSource
	}
	in := f.in
	if target == nil || *target != in.Sample.Target {
		in.Sample = nil
	}
	return fn(in, func(time.Time) error { return ctx.Err() })
}
func TestLinuxMountWatchAPIAuthenticationOptInAndReadPurity(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	id := "agent_" + strings.Repeat("a", 32)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	target := linuxmountwatch.Target{MountPoint: "/var", Filesystem: "ext4", FilesystemGroup: "fs_8_1"}
	f := &mountSourceFixture{fixtureHealthSource: fixtureHealthSource{now: now, input: health.Input{DeviceID: id, Authorized: true}}, in: linuxmountwatch.Input{DeviceID: id, Identity: strings.Repeat("b", 64), SourceToken: "mountsource_" + strings.Repeat("c", 32), AuthorityUntil: now.Add(time.Hour), Available: true, Reason: "none", Options: []linuxmountwatch.Target{target}, Generation: &linuxmountwatch.Generation{Sequence: 1, ID: "sample_" + strings.Repeat("d", 32), CapturedAt: now, ReceivedAt: now}, Sample: &linuxmountwatch.Sample{Target: target, MountID: "mount_3", UsedPercent: 95, TotalBytes: 1000, AvailableBytes: 50}}}
	o.app.health = &healthMonitor{store: o.app.store, source: f}
	path := "/api/devices/" + id + "/mount-watch"
	r, _ := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 401 {
		t.Fatal(r.StatusCode)
	}
	_, session := o.login(t)
	csrf := session["csrfToken"].(string)
	r, v := o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["revision"] != "0" {
		t.Fatal(r.StatusCode, v)
	}
	if os.Getenv("UPDATE_MOUNT_WATCH_FIXTURE") == "1" {
		raw, _ := json.MarshalIndent(v, "", "  ")
		if e := os.WriteFile("../../web/src/linux-mount-watch-go-fixture.json", append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	body := map[string]any{"requestId": "mountrequest_" + strings.Repeat("e", 32), "expectedRevision": "0", "sourceToken": f.in.SourceToken, "operation": "enable", "mountPoint": "/var", "filesystem": "ext4", "filesystemGroup": "fs_8_1", "threshold": 90, "recovery": 80, "retentionAcknowledged": true, "incidentId": ""}
	r, _ = o.call(t, "POST", path, body, "", nil)
	if r.StatusCode != 403 {
		t.Fatal("missing CSRF", r.StatusCode)
	}
	r, v = o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 200 || v["revision"] != "1" {
		t.Fatal(r.StatusCode, v)
	}
	r, v = o.call(t, "GET", path, nil, "", nil)
	if r.StatusCode != 200 || v["check"].(map[string]any)["condition"] != "unknown" {
		t.Fatal("GET evaluated", r.StatusCode, v)
	}
	r, v = o.call(t, "POST", path, body, csrf, nil)
	if r.StatusCode != 200 || v["revision"] != "1" {
		t.Fatal("exact retry", r.StatusCode, v)
	}
	r, _ = o.call(t, "GET", path+"?target=/tmp", nil, "", nil)
	if r.StatusCode != 400 {
		t.Fatal("query accepted", r.StatusCode)
	}
}

func TestLinuxMountWatchMonitorFailureBreaksConfirmation(t *testing.T) {
	o := newOperatorFixture(t, time.Hour)
	id := "agent_" + strings.Repeat("a", 32)
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	target := linuxmountwatch.Target{MountPoint: "/var", Filesystem: "ext4", FilesystemGroup: "fs_8_1"}
	in := linuxmountwatch.Input{DeviceID: id, Identity: strings.Repeat("b", 64), SourceToken: "mountsource_" + strings.Repeat("c", 32), AuthorityUntil: at.Add(time.Hour), Available: true, Reason: "none", Generation: &linuxmountwatch.Generation{Sequence: 1, ID: fmt.Sprintf("sample_%032x", 1), CapturedAt: at, ReceivedAt: at}, Sample: &linuxmountwatch.Sample{Target: target, MountID: "mount_3", UsedPercent: 95, TotalBytes: 1000, AvailableBytes: 50}}
	f := &mountSourceFixture{fixtureHealthSource: fixtureHealthSource{now: at}, in: in}
	m := &healthMonitor{store: o.app.store, source: f}
	c := linuxmountwatch.Command{RequestID: "mountrequest_" + strings.Repeat("e", 32), SourceToken: in.SourceToken, Operation: "enable", Target: &target, Threshold: 90, Recovery: 80, RetentionAcknowledged: true}
	_, _, e := m.store.UpdateLinuxMountWatches(context.Background(), in, &c, false, f.Now, func(time.Time) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	advance := func(seq uint64, sec int) {
		f.now = at.Add(time.Duration(sec) * time.Second)
		f.in.Generation = &linuxmountwatch.Generation{Sequence: seq, ID: fmt.Sprintf("sample_%032x", seq), CapturedAt: f.now, ReceivedAt: f.now}
	}
	advance(2, 30)
	if e = o.app.evaluateLinuxMountWatches(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	state, _ := m.store.LinuxMountWatchState(context.Background(), id)
	if state.Check.Bad != 1 {
		t.Fatal("fixture not pending")
	}
	f.failure = errors.New("denied source")
	f.now = at.Add(40 * time.Second)
	if e = o.app.evaluateLinuxMountWatches(context.Background(), m); e == nil {
		t.Fatal("missing source error")
	}
	state, _ = m.store.LinuxMountWatchState(context.Background(), id)
	if state.Check.Condition != "unknown" || state.Check.Bad != 0 {
		t.Fatal("failed pass retained confirmation")
	}
	f.failure = nil
	advance(3, 60)
	if e = o.app.evaluateLinuxMountWatches(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	state, _ = m.store.LinuxMountWatchState(context.Background(), id)
	if len(state.Incidents) != 0 || state.Check.Bad != 1 {
		t.Fatal("confirmation spanned source failure")
	}
	// The separate watch may fail without relabeling old Health readiness.
	f.failure = errors.New("denied source")
	f.input = health.Input{DeviceID: id, Authorized: true}
	o.app.health = m
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := false
	if e = o.app.RunHealthMonitorObserved(ctx, nil, func(_ time.Time, healthError error) {
		observed = true
		if healthError != nil {
			t.Errorf("mount failure altered Health observer: %v", healthError)
		}
		cancel()
	}); e != nil || !observed {
		t.Fatal("observer loop", e)
	}
}
