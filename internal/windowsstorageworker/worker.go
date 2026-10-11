// Package windowsstorageworker owns the lifetime of an isolated storage-context read.
// Only the current executable and a fixed private worker mode can be launched.
// The child must independently authenticate the installed identity and grant.
// Killing this process bounds the local worker lifetime, not provider service-internal
// activity or memory. Native Windows acceptance remains a separate gate.
package windowsstorageworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"localrmm/internal/windowsstorage"
)

// WorkerArgument is an internal dispatch mode, not a consent or installation
// command. The entry point must reject additional arguments and use Serve with
// an installed-identity resolver; stdin alone cannot authorize a native read.
const WorkerArgument = "--internal-windows-storage-context-worker"
const DisksWorkerArgument = "--internal-windows-storage-disks-worker"

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
func Collect(ctx context.Context, req windowsstorage.Request) (windowsstorage.Snapshot, error) {
	return collectProviders(ctx, req, windowsstorage.ProviderBudget, []commandFactory{newWorkerCommand, newDisksCommand})
}

// Independent source workers share the fixed parent budget; a stuck provider
// cannot erase completed siblings. Drive mapping and physical-disk provider availability remain independent.
func collectProviders(ctx context.Context, req windowsstorage.Request, limit time.Duration, commands []commandFactory) (windowsstorage.Snapshot, error) {
	if ctx == nil || limit <= 0 || len(commands) != 2 {
		return windowsstorage.Snapshot{}, windowsstorage.ErrInvalid
	}
	if e := validateRequest(req); e != nil {
		return windowsstorage.Snapshot{}, e
	}
	result := windowsstorage.Empty(req, windowsstorage.ErrBudget.Error())
	for i, commandFor := range commands {
		if commandFor == nil {
			return windowsstorage.Snapshot{}, windowsstorage.ErrInvalid
		}
		if e := ctx.Err(); e != nil {
			return windowsstorage.Snapshot{}, e
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
			return windowsstorage.Snapshot{}, e
		}
		switch i {
		case 0:
			result.Drives = source.Drives
		case 1:
			result.Disks = source.Disks
		}
	}
	return windowsstorage.FitBudget(result, windowsstorage.MaxBytes)
}

// commandFactory and the adjustable budget are private fixture seams. Runtime
// callers cannot choose another executable, arguments, environment or timeout.
type commandFactory func(context.Context) (*exec.Cmd, error)

func newWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, windowsstorage.ErrUnavailable
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
func newDisksCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, DisksWorkerArgument)
}

func collect(ctx context.Context, req windowsstorage.Request, budget time.Duration, commandFor commandFactory) (windowsstorage.Snapshot, error) {
	if ctx == nil || commandFor == nil || budget <= 0 {
		return windowsstorage.Snapshot{}, windowsstorage.ErrInvalid
	}
	raw, err := encodeRequest(req)
	if err != nil {
		return windowsstorage.Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return windowsstorage.Snapshot{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	command, err := commandFor(bounded)
	if err != nil || command == nil {
		return unavailable(ctx, req, windowsstorage.ErrUnavailable)
	}
	env, err := workerEnvironment()
	if err != nil {
		return unavailable(ctx, req, windowsstorage.ErrUnavailable)
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
		return windowsstorage.Snapshot{}, err
	}
	if output.exceeded {
		return unavailable(ctx, req, windowsstorage.ErrBounds)
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return unavailable(ctx, req, windowsstorage.ErrBudget)
	}
	if err != nil {
		return unavailable(ctx, req, windowsstorage.ErrUnavailable)
	}
	snapshot, err := windowsstorage.Decode(output.Bytes())
	if err != nil || windowsstorage.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return unavailable(ctx, req, windowsstorage.ErrMetadata)
	}
	if err := ctx.Err(); err != nil {
		return windowsstorage.Snapshot{}, err
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
	if b.exceeded || len(p) > windowsstorage.MaxBytes-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, windowsstorage.ErrBounds
	}
	return b.buffer.Write(p)
}

func unavailable(ctx context.Context, req windowsstorage.Request, reason error) (windowsstorage.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return windowsstorage.Snapshot{}, err
	}
	return emptySnapshot(req, reason.Error()), nil
}

func emptySnapshot(req windowsstorage.Request, reason string) windowsstorage.Snapshot {
	return windowsstorage.Empty(req, reason)
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
	resolve func(context.Context, windowsstorage.Request) (windowsstorage.Request, error),
	collectNative func(context.Context, windowsstorage.Request) (windowsstorage.Snapshot, error),
) error {
	if ctx == nil || in == nil || out == nil || resolve == nil || collectNative == nil {
		return windowsstorage.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return windowsstorage.ErrInvalid
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
			return windowsstorage.ErrInvalid
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
	if windowsstorage.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return windowsstorage.ErrInvalid
	}
	response, err := windowsstorage.Encode(snapshot)
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
