// Package windowshistoryworker isolates one explicitly selected event-content read
// in an owned child process. Stdin metadata cannot confer authority: the child
// independently authenticates the installed identity and enabled local grant,
// and durably consumes the request before invoking its reader. No content is
// persisted here, and no synchronous native call is abandoned in a goroutine.
package windowshistoryworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"localrmm/internal/windowseventhistory"
	"localrmm/internal/windowshistoryrequest"
)

const (
	// WorkerArgument is a private dispatch mode, never a local grant command.
	// The executable must reject extra arguments and independently verify its
	// restricted service identity, live owning parent and protected layout.
	WorkerArgument   = "--internal-windows-event-history-worker"
	WorkerBudget     = 10 * time.Second
	MaxResponseBytes = 512 << 10
	pipeWaitDelay    = 100 * time.Millisecond
)

var (
	ErrUnavailable = errors.New("windows_history_worker_unavailable")
	ErrBudget      = errors.New("windows_history_worker_budget_exhausted")
	ErrBounds      = errors.New("windows_history_worker_output_limit")
	ErrMetadata    = errors.New("windows_history_worker_invalid_response")
)

// Gather owns and synchronously reaps the fixed current-executable worker. Its
// deadline is the earliest of caller cancellation, ten seconds and the original
// request expiry. Output overflow kills the child; stderr goes to the null
// device. WaitDelay bounds pipes retained by descendants, but does not claim to
// kill arbitrary descendants or bound unrelated OS activity. Failures are fixed
// errors, never subprocess/source prose or a fabricated empty successful report.
func Gather(ctx context.Context, req Request) (windowseventhistory.Report, error) {
	return gather(ctx, req, WorkerBudget, newWorkerCommand)
}

// Adjustable process construction and budget remain private inert-fixture seams.
type commandFactory func(context.Context) (*exec.Cmd, error)

func newWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, ErrUnavailable
	}
	command := exec.CommandContext(ctx, executable, WorkerArgument)
	command.Dir = filepath.Dir(executable)
	return command, nil
}

func gather(ctx context.Context, req Request, budget time.Duration, commandFor commandFactory) (windowseventhistory.Report, error) {
	if ctx == nil || budget <= 0 || commandFor == nil {
		return windowseventhistory.Report{}, windowshistoryrequest.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return windowseventhistory.Report{}, err
	}
	raw, err := encodeRequest(req)
	if err != nil {
		return windowseventhistory.Report{}, err
	}
	// Freeze the original selection before any process callback runs.
	req, err = decodeRequest(raw)
	if err != nil {
		return windowseventhistory.Report{}, err
	}
	if err := validateRequest(req, time.Now().UTC()); err != nil {
		return windowseventhistory.Report{}, err
	}
	deadline := time.Now().Add(budget)
	if req.Description.ExpiresAt.Before(deadline) {
		deadline = req.Description.ExpiresAt
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	command, err := commandFor(bounded)
	if err != nil || command == nil {
		return windowseventhistory.Report{}, processError(ctx, bounded, req, ErrUnavailable)
	}
	env, err := workerEnvironment()
	if err != nil {
		return windowseventhistory.Report{}, processError(ctx, bounded, req, ErrUnavailable)
	}
	output := &boundedOutput{cancel: cancel}
	command.Env = env
	command.Stdin = bytes.NewReader(raw)
	command.Stdout = output
	command.Stderr = nil
	command.WaitDelay = pipeWaitDelay
	// Run waits after Start even when context cancellation or an output-bound
	// failure kills the child, and joins os/exec's finite pipe-copy goroutines.
	err = command.Run()
	if err := ctx.Err(); err != nil {
		return windowseventhistory.Report{}, err
	}
	if output.exceeded {
		return windowseventhistory.Report{}, ErrBounds
	}
	if err != nil || bounded.Err() != nil {
		return windowseventhistory.Report{}, processError(ctx, bounded, req, ErrUnavailable)
	}
	now := time.Now().UTC()
	if err := validateRequest(req, now); err != nil {
		return windowseventhistory.Report{}, err
	}
	report, err := decodeResponse(output.Bytes(), req, now)
	if err != nil {
		return windowseventhistory.Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return windowseventhistory.Report{}, err
	}
	if bounded.Err() != nil {
		return windowseventhistory.Report{}, processError(ctx, bounded, req, ErrUnavailable)
	}
	if err := validateRequest(req, time.Now().UTC()); err != nil {
		return windowseventhistory.Report{}, err
	}
	return report, nil
}

func processError(ctx, bounded context.Context, req Request, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().UTC().Before(req.Description.ExpiresAt) {
		return windowshistoryrequest.ErrExpired
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return ErrBudget
	}
	return fallback
}

type boundedOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

// Do not embed bytes.Buffer: promoted ReadFrom would bypass the bounded Write.
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedOutput) Len() int      { return b.buffer.Len() }
func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.exceeded || len(p) > MaxResponseBytes-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, ErrBounds
	}
	return b.buffer.Write(p)
}

// Serve processes exactly one canonical bounded request synchronously. resolve
// must freshly authenticate installed identity/config/parent and local consent,
// returning the complete exact request before and after capture. consume must
// durably commit the request's monotonic floor under the child's exclusive
// protected store, then release that store before returning success. Parent and
// child must never contend on a parent-held consumption lock during Gather.
// A failed or ambiguous consume must never be retried as a fresh read.
//
// Reader errors are never serialized or returned verbatim. Valid partial,
// bounded or unavailable reports survive an accompanying nonnil source error;
// their strict finite row reasons convey the actual failure. An invalid/missing
// report produces no output. The entry point exits nonzero on error without
// printing diagnostics and owns a fixed orphan watchdog for parent death.
func Serve(ctx context.Context, in io.Reader, out io.Writer,
	resolve func(context.Context, Request) (Request, error),
	consume func(context.Context, Request) error,
	read func(context.Context, Request) (windowseventhistory.Report, error),
) error {
	if ctx == nil || in == nil || out == nil || resolve == nil || consume == nil || read == nil {
		return windowshistoryrequest.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return windowshistoryrequest.ErrInvalid
	}
	req, err := decodeRequest(raw)
	if err != nil {
		return err
	}
	// This deadline also constrains callbacks, but the owning parent's process
	// timeout remains authoritative for synchronous calls that do not cooperate.
	ctx, cancel := context.WithDeadline(ctx, req.Description.ExpiresAt)
	defer cancel()
	verify := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateRequest(req, time.Now().UTC()); err != nil {
			return err
		}
		resolved, err := resolve(ctx, cloneRequest(req))
		if err != nil {
			return safeError(err)
		}
		if !sameRequest(req, resolved) {
			return windowshistoryrequest.ErrInvalid
		}
		return ctx.Err()
	}
	if err := verify(); err != nil {
		return err
	}
	if err := consume(ctx, cloneRequest(req)); err != nil {
		return safeError(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRequest(req, time.Now().UTC()); err != nil {
		return err
	}
	collection, stopCollection := context.WithTimeout(ctx, windowseventhistory.CollectionTimeout)
	report, _ := read(collection, cloneRequest(req))
	stopCollection()
	// A source error never bypasses the second protected authority read.
	if err := verify(); err != nil {
		return err
	}
	response, err := encodeResponse(report, req, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := out.Write(response)
	if err != nil {
		return ErrUnavailable
	}
	if n != len(response) {
		return io.ErrShortWrite
	}
	return nil
}

func safeError(err error) error {
	for _, known := range []error{context.Canceled, context.DeadlineExceeded,
		windowshistoryrequest.ErrInvalid, windowshistoryrequest.ErrDisabled,
		windowshistoryrequest.ErrConflict, windowshistoryrequest.ErrConsumed,
		windowshistoryrequest.ErrExpired, windowshistoryrequest.ErrCanceled} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}
