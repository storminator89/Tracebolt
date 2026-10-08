//go:build windows && tracebolt_fresh_native

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"localrmm/internal/windowsacceptance/freshgate"
)

var errFreshPending = errors.New("fixture claim still pending")

type freshChunk = freshgate.OutputChunk
type freshPTY struct {
	ctx                        context.Context
	input, output              *os.File
	console, process, job      windows.Handle
	chunks                     chan freshChunk
	processDone                chan struct{}
	consoleDone                chan struct{}
	readerDone                 chan struct{}
	discard                    chan struct{}
	closeConsole               sync.Once
	stopReader                 sync.Once
	processExit                uint32
	processErr                 error
	closed                     bool
	closeReaped, closeVerified bool
}

func freshChildEnvironment(bootstrap string) ([]uint16, error) {
	keys := []string{"SystemRoot", "WINDIR", "COMPUTERNAME", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_ACTOR", "GITHUB_ACTOR_ID", "GITHUB_TRIGGERING_ACTOR", "GITHUB_EVENT_NAME", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "TRACEBOLT_FRESH_PROFILE", "TRACEBOLT_FRESH_SOURCE", "TRACEBOLT_FRESH_TEST_SHA256", "TRACEBOLT_FRESH_SERVICE_SHA256", "TRACEBOLT_FRESH_SERVICE_ARTIFACT", "TRACEBOLT_FRESH_MACHINE", "TRACEBOLT_FRESH_RUN_ID", "TRACEBOLT_FRESH_ATTEMPT", "TRACEBOLT_FRESH_EXPIRES_UNIX", "TRACEBOLT_FRESH_APPROVE_SERVICES", "TRACEBOLT_FRESH_APPROVE_IDENTITY", "TRACEBOLT_FRESH_APPROVE_APP_ACLS", "TRACEBOLT_FRESH_APPROVE_FIVE_READ_SCOPES", "TRACEBOLT_FRESH_APPROVE_SYNTHETIC_CONSOLE", "TRACEBOLT_FRESH_APPROVE_LOOPBACK_TLS", "TRACEBOLT_FRESH_APPROVE_RETAIN_FOR_VM_DISPOSAL", "TRACEBOLT_FRESH_APPROVE_STOP_OWNED_SERVICE"}
	entries := []string{"TRACEBOLT_FRESH_ROLE=child", "TRACEBOLT_FRESH_BOOTSTRAP=" + bootstrap, "GOTRACEBACK=none"}
	for _, k := range keys {
		v := os.Getenv(k)
		if strings.ContainsRune(v, 0) {
			return nil, freshgate.ErrGuard
		}
		entries = append(entries, k+"="+v)
	}
	sort.Slice(entries, func(i, j int) bool { return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j]) })
	var block []uint16
	for _, v := range entries {
		x, e := syscall.UTF16FromString(v)
		if e != nil {
			return nil, freshgate.ErrGuard
		}
		block = append(block, x...)
	}
	return append(block, 0), nil
}
func startFreshPTY(ctx context.Context, g *freshgate.Grant, exe, bootstrap string) (p *freshPTY, err error) {
	if ctx == nil || ctx.Err() != nil || (ctx.Err() != nil || !g.Check()) {
		return nil, freshgate.ErrGuard
	}
	env, e := freshChildEnvironment(bootstrap)
	if e != nil {
		return nil, freshgate.ErrGuard
	}
	app, e := windows.UTF16PtrFromString(exe)
	if e != nil {
		return nil, freshgate.ErrGuard
	}
	command, e := windows.UTF16PtrFromString(syscall.EscapeArg(exe) + " -test.run=^TestFreshReadConPTYNative$ -test.count=1 -test.timeout=14m")
	if e != nil {
		return nil, freshgate.ErrGuard
	}
	// Every native resource below follows the manual gate. No shell and no
	// inherited caller handles/environment are used. Input contains no secret yet.
	var inRead, inWrite, outRead, outWrite windows.Handle
	closeH := func(h *windows.Handle) {
		if *h != 0 {
			_ = windows.CloseHandle(*h)
			*h = 0
		}
	}
	defer func() { closeH(&inRead); closeH(&inWrite); closeH(&outRead); closeH(&outWrite) }()
	if windows.CreatePipe(&inRead, &inWrite, nil, 4096) != nil || windows.CreatePipe(&outRead, &outWrite, nil, 4096) != nil {
		return nil, freshgate.ErrGuard
	}
	var console windows.Handle
	if (ctx.Err() != nil || !g.Check()) || windows.CreatePseudoConsole(windows.Coord{X: 240, Y: 80}, inRead, outWrite, 0, &console) != nil {
		return nil, freshgate.ErrGuard
	}
	// Start draining before process creation or any error teardown, because ConPTY
	// close may emit output synchronously. The channel is bounded; Close switches
	// the reader to discard rather than leaving it blocked after a failed Run.
	p = &freshPTY{ctx: ctx, console: console, input: os.NewFile(uintptr(inWrite), "<fresh console input>"), output: os.NewFile(uintptr(outRead), "<fresh console output>"), chunks: make(chan freshChunk, 8), processDone: make(chan struct{}), consoleDone: make(chan struct{}), readerDone: make(chan struct{}), discard: make(chan struct{})}
	inWrite = 0
	outRead = 0
	go p.readOutput()
	succeeded := false
	owned := p
	defer func() {
		if !succeeded {
			closeH(&inRead)
			closeH(&outWrite)
			owned.Close()
			p = nil
			err = freshgate.ErrGuard
		}
	}()
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return nil, freshgate.ErrGuard
	}
	defer attrs.Delete()
	if attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(uintptr(console)), unsafe.Sizeof(console)) != nil {
		return nil, freshgate.ErrGuard
	}
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, freshgate.ErrGuard
	}
	p.job = job
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return nil, freshgate.ErrGuard
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = attrs.List()
	var pi windows.ProcessInformation
	if (ctx.Err() != nil || !g.Check()) || windows.CreateProcess(app, command, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_SUSPENDED, &env[0], nil, &si.StartupInfo, &pi) != nil {
		return nil, freshgate.ErrGuard
	}
	runtime.KeepAlive(env)
	p.process = pi.Process
	defer windows.CloseHandle(pi.Thread)
	go func() {
		defer close(owned.processDone)
		status, e := windows.WaitForSingleObject(owned.process, windows.INFINITE)
		if e != nil || status != windows.WAIT_OBJECT_0 {
			owned.processErr = freshgate.ErrGuard
			return
		}
		owned.processErr = windows.GetExitCodeProcess(owned.process, &owned.processExit)
	}()
	// A child never executes even one instruction until owned by kill-on-close job.
	if windows.AssignProcessToJobObject(job, pi.Process) != nil || (ctx.Err() != nil || !g.Check()) {
		_ = windows.TerminateProcess(pi.Process, 1)
		return nil, freshgate.ErrGuard
	}
	if _, e = windows.ResumeThread(pi.Thread); e != nil {
		return nil, freshgate.ErrGuard
	}
	closeH(&inRead)
	closeH(&outWrite)
	succeeded = true
	return p, nil
}
func (p *freshPTY) readOutput() {
	defer close(p.readerDone)
	defer close(p.chunks)
	b := make([]byte, 4096)
	defer clear(b)
	for {
		n, e := p.output.Read(b)
		var data []byte
		if n > 0 {
			data = append([]byte(nil), b[:n]...)
			clear(b[:n])
		}
		select {
		case p.chunks <- freshChunk{data, e}:
		case <-p.discard:
			clear(data)
		}
		if e != nil {
			return
		}
	}
}
func (p *freshPTY) Input(secret []byte) error {
	if len(secret) != 43 || p.ctx.Err() != nil {
		return freshgate.ErrGuard
	}
	b := make([]byte, 44)
	copy(b, secret)
	b[43] = '\r'
	defer clear(b)
	n, e := p.input.Write(b)
	if e != nil || n != len(b) {
		return freshgate.ErrGuard
	}
	return nil
}
func (p *freshPTY) beginConsoleClose() {
	p.closeConsole.Do(func() { go func() { windows.ClosePseudoConsole(p.console); close(p.consoleDone) }() })
}
func (p *freshPTY) Run(ctx context.Context, guard *freshgate.OutputGuard, input, approve func() error) (freshgate.SessionOutcome, error) {
	return freshgate.ObserveSessionDiagnostic(ctx, guard, freshgate.SessionSteps{Output: p.chunks, Exited: p.processDone, ConsoleClosed: p.consoleDone, ProcessSucceeded: func() bool { return p.processErr == nil && p.processExit == 0 }, CloseConsole: p.beginConsoleClose, Input: input, Approve: func() (bool, error) {
		e := approve()
		if errors.Is(e, errFreshPending) {
			return false, nil
		}
		return e == nil, e
	}})
}

// naturalDiagnostic reads one readiness snapshot published by the existing
// waiter. The channel close synchronizes all three finite facts together. No
// wait, poll or native call is added; teardown/unobserved exits remain unknown.
func (p *freshPTY) naturalDiagnostic() (exit, stage, category string) {
	if p == nil || p.closed {
		return "unknown", "unknown", "unknown"
	}
	select {
	case <-p.processDone:
		if p.processErr != nil {
			return "unknown", "unknown", "unknown"
		}
		stage, category = freshgate.DecodeChildFailureExit(p.processExit)
		if p.processExit == 0 {
			return "zero", stage, category
		}
		return "nonzero", stage, category
	default:
		return "unknown", "unknown", "unknown"
	}
}

func (p *freshPTY) Close() (reaped, closed bool) {
	if p == nil {
		return true, true
	}
	if p.closed {
		return p.closeReaped, p.closeVerified
	}
	p.closed = true
	cleanupOK := true
	defer func() { closed = closed && cleanupOK; p.closeReaped, p.closeVerified = reaped, closed }()
	p.stopReader.Do(func() { close(p.discard) })
	// Closing the job terminates only this test child and descendants; SCM-owned
	// application service/state is intentionally retained under the disposal grant.
	if p.job != 0 {
		if windows.TerminateJobObject(p.job, 1) != nil {
			cleanupOK = false
		}
		if windows.CloseHandle(p.job) != nil {
			cleanupOK = false
		}
		p.job = 0
	}
	if p.process != 0 {
		select {
		case <-p.processDone:
			reaped = p.processErr == nil
		case <-time.After(5 * time.Second):
			_ = windows.TerminateProcess(p.process, 1)
			select {
			case <-p.processDone:
				reaped = p.processErr == nil
			case <-time.After(5 * time.Second):
			}
		}
	} else {
		reaped = true
	}
	if p.input != nil {
		if p.input.Close() != nil {
			cleanupOK = false
		}
	}
	p.beginConsoleClose()
	select {
	case <-p.consoleDone:
		closed = true
	case <-time.After(10 * time.Second):
	}
	if p.output != nil {
		if p.output.Close() != nil {
			cleanupOK = false
		}
	}
	select {
	case <-p.readerDone:
	case <-time.After(5 * time.Second):
		closed = false
	}
	drain := true
	for drain {
		select {
		case chunk, ok := <-p.chunks:
			if !ok {
				drain = false
			} else {
				clear(chunk.Data)
			}
		default:
			drain = false
		}
	}
	if p.process != 0 && reaped {
		if windows.CloseHandle(p.process) != nil {
			cleanupOK = false
		}
		p.process = 0
	}
	return reaped, closed
}

// These cases only inspect inert waiter state. They make no Windows API calls.
func TestFreshNaturalExitDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name         string
		done, closed bool
		code         uint32
		err          error
		want         string
	}{
		{"unobserved", false, false, 0, nil, "unknown"},
		{"natural zero", true, false, 0, nil, "zero"},
		{"natural nonzero", true, false, 1, nil, "nonzero"},
		{"arbitrary exit", true, false, 0xffffffff, nil, "nonzero"},
		{"wait failed", true, false, 0, freshgate.ErrGuard, "unknown"},
		{"cleanup zero", true, true, 0, nil, "unknown"},
		{"cleanup nonzero", true, true, 1, nil, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &freshPTY{processDone: make(chan struct{}), closed: tc.closed, processExit: tc.code, processErr: tc.err}
			if tc.done {
				close(p.processDone)
			}
			if got, stage, category := p.naturalDiagnostic(); got != tc.want {
				t.Fatalf("finite exit = %q, want %q", got, tc.want)
			} else if got == "zero" && (stage != "none" || category != "none") || got != "zero" && (stage != "unknown" || category != "unknown") {
				t.Fatal("incoherent natural diagnosis")
			}
		})
	}
	var missing *freshPTY
	if exit, stage, category := missing.naturalDiagnostic(); exit != "unknown" || stage != "unknown" || category != "unknown" {
		t.Fatal("missing child not unknown")
	}
}

func TestFreshNaturalDiagnosticKnownFailureSnapshot(t *testing.T) {
	for _, pair := range freshgate.ChildFailurePairs() {
		for _, done := range []bool{false, true} {
			for _, closed := range []bool{false, true} {
				for _, waitError := range []bool{false, true} {
					p := &freshPTY{processDone: make(chan struct{}), closed: closed, processExit: uint32(freshgate.ChildFailureExitCode(pair[0], pair[1]))}
					if done {
						close(p.processDone)
					}
					if waitError {
						p.processErr = freshgate.ErrGuard
					}
					exit, stage, category := p.naturalDiagnostic()
					if done && !closed && !waitError {
						if exit != "nonzero" || stage != pair[0] || category != pair[1] {
							t.Fatal("natural diagnostic lost")
						}
					} else if exit != "unknown" || stage != "unknown" || category != "unknown" {
						t.Fatal("unobserved or forced failure inferred")
					}
				}
			}
		}
	}
}
