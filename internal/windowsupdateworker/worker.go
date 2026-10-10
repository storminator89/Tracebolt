// Package windowsupdateworker owns the lifetime of an isolated cached-WUA read.
// Only the current executable and a fixed private worker mode can be launched.
// The child must independently authenticate the installed identity and grant.
// Killing this process bounds the local worker lifetime, not WUA service-internal
// activity or memory. Native Windows acceptance remains a separate gate.
package windowsupdateworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"localrmm/internal/windowsupdates"
)

// WorkerArgument is an internal dispatch mode, not a consent or installation
// command. The entry point must reject additional arguments and use Serve with
// an installed-identity resolver; stdin alone cannot authorize a native read.
const WorkerArgument = "--internal-windows-update-worker"

const pipeWaitDelay = 100 * time.Millisecond

// Collect validates the request before starting the fixed current-executable
// worker. The worker receives no credentials, config paths or arbitrary query,
// arguments or inherited environment. Windows receives only the OS-derived
// SystemRoot required by process startup. Its stdin and stdout are private pipes.
//
// Caller cancellation kills and synchronously reaps the child and returns the
// caller's context error. The independent 15-second budget instead produces an
// unavailable/budget snapshot, allowing ordinary inventory reporting to continue.
// Process startup/exit and malformed responses produce finite unavailable
// snapshots. WaitDelay also bounds waits on pipe handles retained by descendants;
// it does not kill arbitrary descendants or promise to stop a WUA service.
func Collect(ctx context.Context, req windowsupdates.Request) (windowsupdates.Snapshot, error) {
	return collect(ctx, req, windowsupdates.CollectionBudget, newWorkerCommand)
}

// commandFactory and the adjustable budget are private fixture seams. Runtime
// callers cannot choose another executable, arguments, environment or timeout.
type commandFactory func(context.Context) (*exec.Cmd, error)

func newWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, windowsupdates.ErrUnavailable
	}
	command := exec.CommandContext(ctx, executable, WorkerArgument)
	command.Dir = filepath.Dir(executable)
	return command, nil
}

func collect(ctx context.Context, req windowsupdates.Request, budget time.Duration, commandFor commandFactory) (windowsupdates.Snapshot, error) {
	if ctx == nil || commandFor == nil || budget <= 0 {
		return windowsupdates.Snapshot{}, windowsupdates.ErrInvalid
	}
	raw, err := encodeRequest(req)
	if err != nil {
		return windowsupdates.Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return windowsupdates.Snapshot{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	command, err := commandFor(bounded)
	if err != nil || command == nil {
		return unavailable(ctx, req, windowsupdates.ErrUnavailable)
	}
	env, err := workerEnvironment()
	if err != nil {
		return unavailable(ctx, req, windowsupdates.ErrUnavailable)
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
		return windowsupdates.Snapshot{}, err
	}
	if output.exceeded {
		return unavailable(ctx, req, windowsupdates.ErrBounds)
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return unavailable(ctx, req, windowsupdates.ErrBudget)
	}
	if err != nil {
		return unavailable(ctx, req, windowsupdates.ErrUnavailable)
	}
	snapshot, err := windowsupdates.Decode(output.Bytes())
	if err != nil || windowsupdates.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return unavailable(ctx, req, windowsupdates.ErrMetadata)
	}
	if err := ctx.Err(); err != nil {
		return windowsupdates.Snapshot{}, err
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
	if b.exceeded || len(p) > windowsupdates.MaxBytes-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, windowsupdates.ErrBounds
	}
	return b.buffer.Write(p)
}

func unavailable(ctx context.Context, req windowsupdates.Request, reason error) (windowsupdates.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return windowsupdates.Snapshot{}, err
	}
	return emptySnapshot(req, reason.Error()), nil
}

func emptySnapshot(req windowsupdates.Request, reason string) windowsupdates.Snapshot {
	return windowsupdates.Snapshot{
		SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope,
		GrantID: req.Consent.GrantID, GenerationID: req.GenerationID,
		CollectedAt: req.CollectedAt, Source: "wua-cache", CacheFreshness: "unknown",
		Quality: "unavailable", Reason: reason, Rows: []windowsupdates.Update{},
	}
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
	resolve func(context.Context, windowsupdates.Request) (windowsupdates.Request, error),
	collectNative func(context.Context, windowsupdates.Request) (windowsupdates.Snapshot, error),
) error {
	if ctx == nil || in == nil || out == nil || resolve == nil || collectNative == nil {
		return windowsupdates.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return windowsupdates.ErrInvalid
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
			return windowsupdates.ErrInvalid
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
	if windowsupdates.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return windowsupdates.ErrInvalid
	}
	response, err := windowsupdates.Encode(snapshot)
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
