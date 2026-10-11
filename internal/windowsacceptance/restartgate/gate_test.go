package restartgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func cli(rejection bool) []byte {
	fields := map[string]any{"outcome": "running-observed", "phase": "complete", "stopAttempted": true, "stopRequested": true, "stoppedObserved": true, "startAttempted": true, "startRequested": true, "runningObserved": true, "lastObservedState": 4, "observations": 6, "stateRetained": true}
	if rejection {
		fields["outcome"] = "not-requested"
		fields["phase"] = "receipt"
		fields["observations"] = 0
		delete(fields, "lastObservedState")
		for _, k := range []string{"stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved"} {
			fields[k] = false
		}
	}
	raw, _ := json.Marshal(fields)
	return append(raw, '\n')
}
func result(rejection bool) CommandResult {
	code := 0
	if rejection {
		code = 1
	}
	return CommandResult{Exited: true, ExitCode: code, Stdout: cli(rejection)}
}

func TestExactCLIResultGrammar(t *testing.T) {
	for _, negative := range []bool{false, true} {
		original := result(negative)
		if ValidateCLI(original.Stdout, original.ExitCode, negative) != nil {
			t.Fatal("production shape rejected")
		}
		for _, key := range []string{"outcome", "phase", "stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved", "observations", "stateRetained"} {
			var fields map[string]any
			_ = json.Unmarshal(original.Stdout, &fields)
			delete(fields, key)
			raw, _ := json.Marshal(fields)
			if ValidateCLI(raw, original.ExitCode, negative) == nil {
				t.Fatal("missing field admitted")
			}
			fields[key] = nil
			raw, _ = json.Marshal(fields)
			if ValidateCLI(raw, original.ExitCode, negative) == nil {
				t.Fatal("null admitted")
			}
		}
		bad := [][]byte{append(append([]byte(nil), original.Stdout...), original.Stdout...), []byte(`{"outcome":"not-requested","outcome":"not-requested"}`), []byte("null"), []byte("[]"), []byte(strings.Repeat(" ", OutputLimit+1)), append([]byte(`{"extra":true,`), original.Stdout[1:]...), append([]byte(`{"phase":"receipt",`), original.Stdout[1:]...)}
		for _, raw := range bad {
			if ValidateCLI(raw, original.ExitCode, negative) == nil {
				t.Fatal("nonexact result admitted")
			}
		}
		if ValidateCLI(original.Stdout, 2, negative) == nil {
			t.Fatal("wrong exit admitted")
		}
	}
}
func TestCLINeverAdmitsEffectfulNegativeOrIncompletePositive(t *testing.T) {
	for _, negative := range []bool{false, true} {
		for _, key := range []string{"stopAttempted", "stopRequested", "stoppedObserved", "startAttempted", "startRequested", "runningObserved", "stateRetained", "observations", "outcome", "phase"} {
			var f map[string]any
			_ = json.Unmarshal(cli(negative), &f)
			switch v := f[key].(type) {
			case bool:
				f[key] = !v
			case float64:
				f[key] = 185
			case string:
				f[key] = "intervention-required"
			}
			raw, _ := json.Marshal(f)
			code := 0
			if negative {
				code = 1
			}
			if ValidateCLI(raw, code, negative) == nil {
				t.Fatal("incomplete/effectful admitted")
			}
		}
	}
}
func TestSequenceRequiresExactlyTwoOrderedCommands(t *testing.T) {
	s := NewSequence()
	for _, err := range []error{s.BeginRejection(), s.ConfirmRejection(result(true), true, true), s.ReleaseLease(true), s.BeginRestart(), s.ConfirmRestart(result(false))} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if !s.Ready() {
		t.Fatal("sequence not ready")
	}
	if s.BeginRestart() == nil || s.Ready() {
		t.Fatal("retry admitted")
	}
}
func TestSequenceUncertaintyAndEveryFailedPrerequisiteArePermanent(t *testing.T) {
	for _, failure := range []string{"order", "uncertain", "no-exit", "effect", "process", "lease", "release", "late", "positive"} {
		t.Run(failure, func(t *testing.T) {
			s := NewSequence()
			if failure == "order" {
				_ = s.BeginRestart()
			} else {
				_ = s.BeginRejection()
				c := result(true)
				if failure == "uncertain" {
					c.Uncertain = true
				}
				if failure == "no-exit" {
					c.Exited = false
				}
				if failure == "effect" {
					c.Stdout = cli(false)
				}
				_ = s.ConfirmRejection(c, failure != "process", failure != "lease")
				_ = s.ReleaseLease(failure != "release")
				if failure == "late" {
					s.MarkUnknown()
				}
				_ = s.BeginRestart()
				c = result(false)
				if failure == "positive" {
					c.ExitCode = 1
				}
				_ = s.ConfirmRestart(c)
			}
			if s.Ready() || s.BeginRejection() == nil || s.BeginRestart() == nil {
				t.Fatal("failed run became reusable")
			}
		})
	}
}

type fakeChild struct {
	startErr, errorWait error
	wait                func()
	exited              bool
	code                int
}

func (f *fakeChild) Start() error { return f.startErr }
func (f *fakeChild) Wait() error {
	if f.wait != nil {
		f.wait()
	}
	return f.errorWait
}
func (f *fakeChild) Exit() (bool, int) { return f.exited, f.code }
func exe(t *testing.T) string          { return filepath.Join(t.TempDir(), "fixed-installed-cli") }

func TestSupervisorFiniteSuccessAndFailureWithoutRawStderr(t *testing.T) {
	for _, negative := range []bool{false, true} {
		r, e := supervise(context.Background(), exe(t), time.Now().Add(time.Second), nil, func(_ string, out, stderr io.Writer) child {
			c := &fakeChild{exited: true}
			if negative {
				c.code = 1
				c.errorWait = &exec.ExitError{}
			}
			c.wait = func() {
				_, _ = out.Write(cli(negative))
				if negative {
					_, _ = stderr.Write([]byte("private diagnostic must not escape"))
				}
			}
			return c
		})
		if e != nil || !r.Exited || r.Uncertain || r.StderrSeen != negative || ValidateCLI(r.Stdout, r.ExitCode, negative) != nil {
			t.Fatal("finite command failed")
		}
	}
}
func TestSupervisorDeadlineIsUnknownAndStillWaitsWithoutKilling(t *testing.T) {
	done := make(chan struct{})
	unknown := make(chan string, 1)
	returned := make(chan CommandResult, 1)
	go func() {
		r, _ := supervise(context.Background(), exe(t), time.Now().Add(30*time.Millisecond), func(code string) { unknown <- code }, func(_ string, out, stderr io.Writer) child {
			return &fakeChild{exited: true, wait: func() { <-done; _, _ = out.Write(cli(false)) }}
		})
		returned <- r
	}()
	select {
	case code := <-unknown:
		if code != "deadline" {
			t.Fatal("wrong finite code")
		}
	case <-time.After(time.Second):
		t.Fatal("missing uncertainty notice")
	}
	select {
	case <-returned:
		t.Fatal("abandoned outstanding process")
	default:
	}
	close(done)
	r := <-returned
	if !r.Exited || !r.Uncertain || len(r.Stdout) != 0 {
		t.Fatal("late success erased uncertainty")
	}
}
func TestSupervisorCancellationRetainsWaitAndCannotRecover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	done := make(chan struct{})
	notice := make(chan struct{}, 1)
	returned := make(chan CommandResult, 1)
	path := exe(t)
	go func() {
		r, _ := supervise(ctx, path, time.Now().Add(time.Second), func(string) { notice <- struct{}{} }, func(_ string, out, stderr io.Writer) child {
			return &fakeChild{exited: true, wait: func() { close(started); <-done; _, _ = out.Write(cli(false)) }}
		})
		returned <- r
	}()
	<-started
	cancel()
	<-notice
	select {
	case <-returned:
		t.Fatal("abandoned canceled process")
	default:
	}
	close(done)
	r := <-returned
	if !r.Uncertain || !r.Exited {
		t.Fatal("cancel recovered")
	}
}
func TestSupervisorOutputOverflowDrainsWithoutRetentionOrAbandonment(t *testing.T) {
	for _, which := range []string{"stdout", "stderr"} {
		t.Run(which, func(t *testing.T) {
			var written atomic.Int64
			var notices atomic.Int32
			r, e := supervise(context.Background(), exe(t), time.Now().Add(time.Second), func(code string) {
				if code != "output_overflow" {
					t.Error("wrong finite code")
				}
				notices.Add(1)
			}, func(_ string, out, stderr io.Writer) child {
				return &fakeChild{exited: true, wait: func() {
					dest := out
					if which == "stderr" {
						dest = stderr
					}
					for i := 0; i < 128; i++ {
						n, e := dest.Write(make([]byte, 4096))
						if e != nil {
							t.Error("drain blocked")
						}
						written.Add(int64(n))
					}
				}}
			})
			if !errors.Is(e, ErrUnknown) || !r.Uncertain || len(r.Stdout) != 0 || written.Load() != 128*4096 || notices.Load() != 1 {
				t.Fatal("overflow did not safely drain")
			}
		})
	}
}
func TestSupervisorRefusesBeforeLaunchAndUnknownIOCannotPass(t *testing.T) {
	path := exe(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		ctx      context.Context
		path     string
		deadline time.Time
	}{{nil, path, time.Now().Add(time.Second)}, {ctx, path, time.Now().Add(time.Second)}, {context.Background(), "relative", time.Now().Add(time.Second)}, {context.Background(), path, time.Now().Add(-time.Second)}} {
		_, e := supervise(c.ctx, c.path, c.deadline, nil, func(string, io.Writer, io.Writer) child { t.Fatal("unauthorized launch"); return nil })
		if e == nil {
			t.Fatal("missing refusal")
		}
	}
	r, e := supervise(context.Background(), path, time.Now().Add(time.Second), nil, func(string, io.Writer, io.Writer) child {
		return &fakeChild{exited: true, errorWait: errors.New("private IO detail")}
	})
	if !r.Uncertain || !errors.Is(e, ErrUnknown) {
		t.Fatal("IO failure admitted")
	}
}
func TestWallDriftUsesMonotonicDuration(t *testing.T) {
	a := time.Now()
	b := a.Add(time.Second)
	if wallDrift(a, b) != 0 {
		t.Fatal("stable clock rejected")
	}
}

func TestSupervisorNotificationPanicCannotAbandonStartedProcess(t *testing.T) {
	var completed atomic.Bool
	r, e := supervise(context.Background(), exe(t), time.Now().Add(15*time.Millisecond), func(string) { panic("private observer failure") }, func(_ string, out, stderr io.Writer) child {
		return &fakeChild{exited: true, wait: func() { time.Sleep(35 * time.Millisecond); completed.Store(true); _, _ = out.Write(cli(false)) }}
	})
	if !completed.Load() || !r.Exited || !r.Uncertain || !errors.Is(e, ErrUnknown) {
		t.Fatal("report failure abandoned process")
	}
}

func TestFixedCommandHasNoInjectedArgumentsOrEnvironment(t *testing.T) {
	t.Setenv("TRACEBOLT_RESTART_REPORT_HANDLE", "never-inherit")
	t.Setenv("GODEBUG", "never-inherit")
	t.Setenv("SYNTHETIC_PRIVATE_SECRET", "never-inherit")
	path := exe(t)
	p, ok := fixedCommand(path, io.Discard, io.Discard).(realChild)
	if !ok || !reflect.DeepEqual(p.Args, []string{path, "--restart", "--apply"}) || p.Dir != filepath.Dir(path) || p.Cancel != nil || p.WaitDelay != 0 || p.Stdin != nil {
		t.Fatal("ordinary command contract changed")
	}
	for _, value := range p.Env {
		if strings.Contains(value, "never-inherit") || !strings.HasPrefix(value, "SystemRoot=") {
			t.Fatal("inherited environment")
		}
	}
	if runtime.GOOS == "windows" && len(p.Env) != 1 || runtime.GOOS != "windows" && len(p.Env) != 0 {
		t.Fatal("unexpected environment")
	}
	// Constructed only: no process launch or service observation here.
}
