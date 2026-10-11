// Package restartgate contains inert contracts for the separately approved
// own-agent restart acceptance case. Importing it performs no native operation.
package restartgate

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const OutputLimit = 16 << 10

var ErrRejected = errors.New("restart acceptance rejected")
var ErrUnknown = errors.New("restart acceptance intervention required")

// CommandResult holds bounded public CLI output only. Stderr is drained and
// counted but never exported. Exited refers to the actual spawned CLI process.
type CommandResult struct {
	Exited     bool
	ExitCode   int
	Stdout     []byte
	StderrSeen bool
	Uncertain  bool
}

type child interface {
	Start() error
	Wait() error
	Exit() (bool, int)
}
type realChild struct{ *exec.Cmd }

func (p realChild) Exit() (bool, int) {
	if p.ProcessState == nil {
		return false, -1
	}
	return p.ProcessState.Exited(), p.ProcessState.ExitCode()
}

type launch func(string, io.Writer, io.Writer) child

// Supervise invokes only the ordinary installed CLI. Cancellation and the
// nominal deadline NEVER kill it, close its pipes or abandon its Wait. A late
// return cannot erase uncertainty. This deliberately is not a hard time bound.
// onUnknown must be nonblocking; it is called at most once with a finite code.
func Supervise(ctx context.Context, executable string, deadline time.Time, onUnknown func(string)) (CommandResult, error) {
	return supervise(ctx, executable, deadline, onUnknown, fixedCommand)
}

func fixedCommand(path string, out, stderr io.Writer) child {
	cmd := exec.Command(path, "--restart", "--apply") // no CommandContext or kill-on-close job
	if isolateCommand(cmd) != nil {
		return nil
	}
	cmd.Dir = filepath.Dir(path)
	cmd.Stdout, cmd.Stderr = out, stderr
	return realChild{cmd}
}

type boundedOutput struct {
	mu       sync.Mutex
	retained []byte
	count    int
	overflow bool
	save     bool
	signal   chan<- struct{}
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := OutputLimit - b.count
	if left > 0 {
		k := len(p)
		if k > left {
			k = left
		}
		if b.save {
			b.retained = append(b.retained, p[:k]...)
		}
		b.count += k
	}
	if n > left && !b.overflow {
		b.overflow = true
		select {
		case b.signal <- struct{}{}:
		default:
		}
	}
	// Discard overflow, still return the full write count to keep draining safely.
	return n, nil
}
func (b *boundedOutput) snapshot() ([]byte, bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.retained...), b.count > 0, b.overflow
}

func supervise(ctx context.Context, executable string, deadline time.Time, onUnknown func(string), spawn launch) (r CommandResult, err error) {
	r.ExitCode = -1
	if ctx == nil || spawn == nil || !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") || deadline.IsZero() || !time.Now().Before(deadline) || ctx.Err() != nil {
		return r, ErrRejected
	}
	signal := make(chan struct{}, 1)
	out := &boundedOutput{save: true, signal: signal}
	stderr := &boundedOutput{signal: signal}
	process := spawn(executable, out, stderr)
	if process == nil {
		return r, ErrRejected
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return r, ErrRejected
	}
	if process.Start() != nil {
		return r, ErrRejected
	}
	// The only goroutine owning Wait always finishes before this function returns.
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	start := time.Now()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	cancelled := ctx.Done()
	timed := timer.C
	unknown := func(code string) {
		if !r.Uncertain {
			r.Uncertain = true
			if onUnknown != nil {
				func() {
					defer func() { _ = recover() }() // reporting failure cannot abandon a live child
					onUnknown(code)
				}()
			}
		}
	}
	for {
		select {
		case waitErr := <-done:
			r.Exited, r.ExitCode = process.Exit()
			var overflow, stderrOverflow bool
			r.Stdout, _, overflow = out.snapshot()
			_, r.StderrSeen, stderrOverflow = stderr.snapshot()
			if overflow || stderrOverflow {
				unknown("output_overflow")
			}
			if ctx.Err() != nil {
				unknown("cancelled")
			}
			now := time.Now()
			if !now.Before(deadline) {
				unknown("deadline")
			}
			if wallDrift(start, now) > time.Second {
				unknown("clock_changed")
			}
			var exitErr *exec.ExitError
			if !r.Exited || (waitErr != nil && !errors.As(waitErr, &exitErr)) {
				unknown("process_io")
			}
			if r.Uncertain {
				clear(r.Stdout)
				r.Stdout = nil
				return r, ErrUnknown
			}
			return r, nil
		case <-cancelled:
			unknown("cancelled")
			cancelled = nil
		case <-timed:
			unknown("deadline")
			timed = nil
		case <-signal:
			unknown("output_overflow")
		case <-tick.C:
			now := time.Now()
			if wallDrift(start, now) > time.Second {
				unknown("clock_changed")
			}
			if !now.Before(deadline) {
				unknown("deadline")
			}
		}
	}
}

func wallDrift(start, end time.Time) time.Duration {
	wall := time.Duration(end.UnixNano() - start.UnixNano())
	drift := wall - end.Sub(start)
	if drift < 0 {
		drift = -drift
	}
	return drift
}
