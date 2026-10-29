package enrollmentclient

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recoveryWriteFixture struct{ writes, telemetry int }

func (*recoveryWriteFixture) Read(string) ([]byte, error)    { return nil, os.ErrNotExist }
func (f *recoveryWriteFixture) Write(string, []byte) error   { f.writes++; return nil }
func (*recoveryWriteFixture) TelemetryExists() (bool, error) { return false, nil }
func (f *recoveryWriteFixture) EnsureTelemetry() error       { f.telemetry++; return nil }
func (*recoveryWriteFixture) Close() error                   { return nil }

func TestServiceRecoveryWriteGuardBlocksLateAndCanceledPublication(t *testing.T) {
	clock := int64(199)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &serviceRecoveryAuthority{deadline: 200, ctx: ctx, now: func() time.Time { return time.Unix(clock, 0) }}
	f := &recoveryWriteFixture{}
	guarded := recoveryEnrollmentStorage{f, a.guard}
	if guarded.Write("ledger.json", nil) != nil || guarded.EnsureTelemetry() != nil || f.writes != 1 || f.telemetry != 1 {
		t.Fatal("guard blocked in-window operation")
	}
	clock = 200
	if guarded.Write("ready.json", nil) != ErrServiceDeadline || guarded.EnsureTelemetry() != ErrServiceDeadline || f.writes != 1 || f.telemetry != 1 {
		t.Fatal("expired operation reached durable storage")
	}
	s := &session{&sessionData{opts: Options{recovery: a}}}
	if _, err := s.publish(); err != ErrServiceDeadline {
		t.Fatal("late publication bypassed entry guard")
	}
	clock = 199
	cancel()
	if !errors.Is(guarded.Write("agent.json", nil), context.Canceled) || !errors.Is(guarded.EnsureTelemetry(), context.Canceled) || f.writes != 1 || f.telemetry != 1 {
		t.Fatal("canceled operation reached storage")
	}
	if _, err := s.publish(); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled publication proceeded")
	}
	ordinary := &session{&sessionData{}}
	if ordinary.guardRecoveryWrite() != nil {
		t.Fatal("ordinary startup acquired recovery deadline")
	}
	if _, err := ResumeServiceRecovery(context.Background(), Bootstrap{Profile: "tls"}, "unused", ServiceRecoveryState{Binding: strings.Repeat("a", 64), DeadlineAt: time.Now().Unix() - 1}); err != ErrServiceDeadline {
		t.Fatal("expired recovery opened state")
	}
}

func TestServiceRecoveryViewKeepsOriginalDeadlineEvenForReadyIdentity(t *testing.T) {
	marker := serviceEnrollment{DeadlineAt: 200}
	binding := serviceEnrollment{ClaimID: "fixture-claim", KeyFingerprint: "fixture-public-key"}
	before := marker
	for _, ready := range []bool{false, true} {
		got, err := serviceRecoveryView(marker, binding, ready, time.Unix(199, 0))
		if err != nil || got.DeadlineAt != 200 || got.Ready != ready || len(got.Binding) != 64 || !reflect.DeepEqual(marker, before) {
			t.Fatal("original evidence changed", err)
		}
		for _, now := range []int64{200, 201} {
			got, err = serviceRecoveryView(marker, binding, ready, time.Unix(now, 0))
			if err != ErrServiceDeadline || got != (ServiceRecoveryState{}) {
				t.Fatal("ready identity extended recovery window")
			}
		}
	}
	a, _ := serviceRecoveryView(marker, binding, false, time.Unix(100, 0))
	binding.KeyFingerprint = "different-key"
	b, _ := serviceRecoveryView(marker, binding, false, time.Unix(100, 0))
	if a.Binding == b.Binding {
		t.Fatal("binding did not pin original key")
	}
	marker.DeadlineStopped = true
	if got, err := serviceRecoveryView(marker, binding, false, time.Unix(100, 0)); err != ErrServiceDeadline || got != (ServiceRecoveryState{}) {
		t.Fatal("durable deadline stop ignored")
	}
	if got, err := InspectServiceRecovery(Bootstrap{Profile: "http-test"}, "unused"); err != ErrBootstrap || got != (ServiceRecoveryState{}) {
		t.Fatal("HTTP recovery reached state")
	}
}
