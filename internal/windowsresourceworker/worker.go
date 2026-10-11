// Package windowsresourceworker owns the lifetime of an isolated CPU and memory context read.
// Only the current executable and a fixed private worker mode can be launched.
// The child must independently authenticate the installed identity and grant.
// Killing this process bounds the local worker lifetime, not provider service-internal
// activity or memory. Native Windows acceptance remains a separate gate.
package windowsresourceworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"localrmm/internal/windowsresourcecontext"
)

// WorkerArgument is an internal dispatch mode, not a consent or installation
// command. The entry point must reject additional arguments and use Serve with
// an installed-identity resolver; stdin alone cannot authorize a native read.
const WorkerArgument = "--internal-windows-resource-context-worker"
const InstalledMemoryWorkerArgument = "--internal-windows-resource-installed-memory-worker"
const MemoryWorkerArgument = "--internal-windows-resource-memory-worker"
const PagefilesWorkerArgument = "--internal-windows-resource-pagefiles-worker"

const pipeWaitDelay = 100 * time.Millisecond

// Collect validates the request before starting the fixed current-executable
// worker. The worker receives no credentials, config paths or arbitrary query,
// arguments or inherited environment. Windows receives only the OS-derived
// SystemRoot required by process startup. Its stdin and stdout are private pipes.
//
// Caller cancellation kills and synchronously reaps the child and returns the
// caller's context error. The independent one-second provider budget instead produces an
// unavailable/budget snapshot, allowing ordinary inventory reporting to continue.
// Process startup/exit and malformed responses produce finite unavailable
// snapshots. WaitDelay also bounds waits on pipe handles retained by descendants;
// it does not kill arbitrary descendants or promise to stop a provider service.
func Collect(ctx context.Context, req windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error) {
	return collectProviders(ctx, req, windowsresourcecontext.ProviderBudget, []commandFactory{newWorkerCommand, newInstalledMemoryCommand, newMemoryCommand, newPagefilesCommand})
}

// Independent source workers share the fixed parent budget; a stuck provider
// cannot erase completed siblings. Pagefiles get a separate final bounded turn.
func collectProviders(ctx context.Context, req windowsresourcecontext.Request, limit time.Duration, commands []commandFactory) (windowsresourcecontext.Snapshot, error) {
	if ctx == nil || limit <= 0 || len(commands) != 4 {
		return windowsresourcecontext.Snapshot{}, windowsresourcecontext.ErrInvalid
	}
	if e := validateRequest(req); e != nil {
		return windowsresourcecontext.Snapshot{}, e
	}
	result := windowsresourcecontext.Empty(req, windowsresourcecontext.ErrBudget.Error())
	for i, commandFor := range commands {
		if commandFor == nil {
			return windowsresourcecontext.Snapshot{}, windowsresourcecontext.ErrInvalid
		}
		if e := ctx.Err(); e != nil {
			return windowsresourcecontext.Snapshot{}, e
		}
		budget := limit
		if deadline, ok := ctx.Deadline(); ok {
			available := (time.Until(deadline) - time.Duration(len(commands)-i)*pipeWaitDelay) / time.Duration(len(commands)-i)
			if available <= 0 {
				continue
			}
			if available < budget {
				budget = available
			}
		}
		source, e := collect(ctx, req, budget, commandFor)
		if e != nil {
			return windowsresourcecontext.Snapshot{}, e
		}
		switch i {
		case 0:
			result.Processors = source.Processors
		case 1:
			result.InstalledMemory = source.InstalledMemory
		case 2:
			result.Memory = source.Memory
		case 3:
			result.Pagefiles = source.Pagefiles
		}
	}
	// Independently valid responses can grow when composed. Keep an explicit
	// complete-source bounds failure rather than erase unrelated memory results.
	if raw, err := json.Marshal(result); err != nil {
		return windowsresourcecontext.Snapshot{}, windowsresourcecontext.ErrInvalid
	} else if len(raw) > windowsresourcecontext.MaxBytes {
		result.Processors = windowsresourcecontext.EmptyProcessors(windowsresourcecontext.ErrBounds.Error())
	}
	return windowsresourcecontext.FitBudget(result, windowsresourcecontext.MaxBytes)
}

// commandFactory and the adjustable budget are private fixture seams. Runtime
// callers cannot choose another executable, arguments, environment or timeout.
type commandFactory func(context.Context) (*exec.Cmd, error)

func newWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, windowsresourcecontext.ErrUnavailable
	}
	command := exec.CommandContext(ctx, executable, WorkerArgument)
	command.Dir = filepath.Dir(executable)
	return command, nil
}

func sourceCommand(ctx context.Context, arg string) (*exec.Cmd, error) {
	c, e := newWorkerCommand(ctx)
	if e != nil {
		return nil, e
	}
	c.Args[1] = arg
	return c, nil
}
func newInstalledMemoryCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, InstalledMemoryWorkerArgument)
}
func newMemoryCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, MemoryWorkerArgument)
}
func newPagefilesCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, PagefilesWorkerArgument)
}

func collect(ctx context.Context, req windowsresourcecontext.Request, budget time.Duration, commandFor commandFactory) (windowsresourcecontext.Snapshot, error) {
	if ctx == nil || commandFor == nil || budget <= 0 {
		return windowsresourcecontext.Snapshot{}, windowsresourcecontext.ErrInvalid
	}
	raw, err := encodeRequest(req)
	if err != nil {
		return windowsresourcecontext.Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return windowsresourcecontext.Snapshot{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	command, err := commandFor(bounded)
	if err != nil || command == nil {
		return unavailable(ctx, req, windowsresourcecontext.ErrUnavailable)
	}
	env, err := workerEnvironment()
	if err != nil {
		return unavailable(ctx, req, windowsresourcecontext.ErrUnavailable)
	}
	output := &boundedOutput{cancel: cancel}
	command.Env = env
	command.Stdin = bytes.NewReader(raw)
	command.Stdout = output
	// nil stderr opens the null device, rather than retaining error prose or
	// creating a second copying goroutine or unbounded stderr buffer.
	command.Stderr = nil
	command.WaitDelay = pipeWaitDelay
	// Run always performs Wait after Start. CommandContext kills on cancellation;
	// WaitDelay closes inherited pipes and joins os/exec's copying goroutines.
	err = command.Run()
	if err := ctx.Err(); err != nil {
		return windowsresourcecontext.Snapshot{}, err
	}
	if output.exceeded {
		return unavailable(ctx, req, windowsresourcecontext.ErrBounds)
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return unavailable(ctx, req, windowsresourcecontext.ErrBudget)
	}
	if err != nil {
		return unavailable(ctx, req, windowsresourcecontext.ErrUnavailable)
	}
	snapshot, err := windowsresourcecontext.Decode(output.Bytes())
	if err != nil || windowsresourcecontext.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return unavailable(ctx, req, windowsresourcecontext.ErrMetadata)
	}
	if err := ctx.Err(); err != nil {
		return windowsresourcecontext.Snapshot{}, err
	}
	return snapshot, nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

// Do not embed bytes.Buffer: its promoted ReadFrom would let io.Copy bypass
// Write and silently defeat the output bound.
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedOutput) Len() int      { return b.buffer.Len() }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.exceeded || len(p) > windowsresourcecontext.MaxBytes-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, windowsresourcecontext.ErrBounds
	}
	return b.buffer.Write(p)
}

func unavailable(ctx context.Context, req windowsresourcecontext.Request, reason error) (windowsresourcecontext.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return windowsresourcecontext.Snapshot{}, err
	}
	return emptySnapshot(req, reason.Error()), nil
}

func emptySnapshot(req windowsresourcecontext.Request, reason string) windowsresourcecontext.Snapshot {
	return windowsresourcecontext.Empty(req, reason)
}

// Serve handles exactly one bounded canonical request. resolve must authenticate
// protected installed identity/config and the current enabled local receipt,
// matching every request field; it must not acquire a parent-held sender lock.
// It runs before native access and again after collection, including collection
// failure. No output is emitted unless both resolutions and the snapshot's exact
// grant/generation/original-capture binding succeed. The entry point should exit
// nonzero on any error and must not print raw errors on stdout.
//
// Serve is deliberately synchronous. in/out are the parent's private pipes, whose
// lifetime the parent owns. A stuck native call, resolver or pipe is stopped by
// the owning parent's process deadline, never an abandoned native-call goroutine.
func Serve(ctx context.Context, in io.Reader, out io.Writer,
	resolve func(context.Context, windowsresourcecontext.Request) (windowsresourcecontext.Request, error),
	collectNative func(context.Context, windowsresourcecontext.Request) (windowsresourcecontext.Snapshot, error),
) error {
	if ctx == nil || in == nil || out == nil || resolve == nil || collectNative == nil {
		return windowsresourcecontext.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return windowsresourcecontext.ErrInvalid
	}
	req, err := decodeRequest(raw)
	if err != nil {
		return err
	}
	verify := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		resolved, err := resolve(ctx, req)
		if err != nil {
			return err
		}
		if !sameRequest(req, resolved) {
			return windowsresourcecontext.ErrInvalid
		}
		return ctx.Err()
	}
	if err := verify(); err != nil {
		return err
	}
	snapshot, collectErr := collectNative(ctx, req)
	if err := verify(); err != nil {
		return err
	}
	if collectErr != nil {
		return collectErr
	}
	if windowsresourcecontext.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return windowsresourcecontext.ErrInvalid
	}
	response, err := windowsresourcecontext.Encode(snapshot)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := out.Write(response)
	if err != nil {
		return err
	}
	if n != len(response) {
		return io.ErrShortWrite
	}
	return nil
}
