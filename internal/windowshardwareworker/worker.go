// Package windowshardwareworker owns the lifetime of an isolated hardware-context read.
// Only the current executable and a fixed private worker mode can be launched.
// The child must independently authenticate the installed identity and grant.
// Killing this process bounds the local worker lifetime, not provider service-internal
// activity or memory. Native Windows acceptance remains a separate gate.
package windowshardwareworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"localrmm/internal/windowshardware"
)

// WorkerArgument is an internal dispatch mode, not a consent or installation
// command. The entry point must reject additional arguments and use Serve with
// an installed-identity resolver; stdin alone cannot authorize a native read.
const WorkerArgument = "--internal-windows-hardware-context-worker"
const FirmwareWorkerArgument = "--internal-windows-hardware-firmware-worker"
const ChassisWorkerArgument = "--internal-windows-hardware-chassis-worker"
const PowerWorkerArgument = "--internal-windows-hardware-power-worker"

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
func Collect(ctx context.Context, req windowshardware.Request) (windowshardware.Snapshot, error) {
	return collectProviders(ctx, req, windowshardware.ProviderBudget, []commandFactory{newWorkerCommand, newFirmwareCommand, newChassisCommand, newPowerCommand})
}

// Independent source workers share the fixed parent budget; a stuck provider
// cannot erase completed siblings. Power gets a separate final bounded turn.
func collectProviders(ctx context.Context, req windowshardware.Request, limit time.Duration, commands []commandFactory) (windowshardware.Snapshot, error) {
	if ctx == nil || limit <= 0 || len(commands) != 4 {
		return windowshardware.Snapshot{}, windowshardware.ErrInvalid
	}
	if e := validateRequest(req); e != nil {
		return windowshardware.Snapshot{}, e
	}
	result := windowshardware.Empty(req, windowshardware.ErrBudget.Error())
	for i, commandFor := range commands {
		if commandFor == nil {
			return windowshardware.Snapshot{}, windowshardware.ErrInvalid
		}
		if e := ctx.Err(); e != nil {
			return windowshardware.Snapshot{}, e
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
			return windowshardware.Snapshot{}, e
		}
		switch i {
		case 0:
			result.System = source.System
		case 1:
			result.Firmware = source.Firmware
		case 2:
			result.Chassis = source.Chassis
		case 3:
			result.Power = source.Power
		}
	}
	return windowshardware.FitBudget(result, windowshardware.MaxBytes)
}

// commandFactory and the adjustable budget are private fixture seams. Runtime
// callers cannot choose another executable, arguments, environment or timeout.
type commandFactory func(context.Context) (*exec.Cmd, error)

func newWorkerCommand(ctx context.Context) (*exec.Cmd, error) {
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, windowshardware.ErrUnavailable
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
func newFirmwareCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, FirmwareWorkerArgument)
}
func newChassisCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, ChassisWorkerArgument)
}
func newPowerCommand(ctx context.Context) (*exec.Cmd, error) {
	return sourceCommand(ctx, PowerWorkerArgument)
}

func collect(ctx context.Context, req windowshardware.Request, budget time.Duration, commandFor commandFactory) (windowshardware.Snapshot, error) {
	if ctx == nil || commandFor == nil || budget <= 0 {
		return windowshardware.Snapshot{}, windowshardware.ErrInvalid
	}
	raw, err := encodeRequest(req)
	if err != nil {
		return windowshardware.Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return windowshardware.Snapshot{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	command, err := commandFor(bounded)
	if err != nil || command == nil {
		return unavailable(ctx, req, windowshardware.ErrUnavailable)
	}
	env, err := workerEnvironment()
	if err != nil {
		return unavailable(ctx, req, windowshardware.ErrUnavailable)
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
		return windowshardware.Snapshot{}, err
	}
	if output.exceeded {
		return unavailable(ctx, req, windowshardware.ErrBounds)
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return unavailable(ctx, req, windowshardware.ErrBudget)
	}
	if err != nil {
		return unavailable(ctx, req, windowshardware.ErrUnavailable)
	}
	snapshot, err := windowshardware.Decode(output.Bytes())
	if err != nil || windowshardware.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return unavailable(ctx, req, windowshardware.ErrMetadata)
	}
	if err := ctx.Err(); err != nil {
		return windowshardware.Snapshot{}, err
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
	if b.exceeded || len(p) > windowshardware.MaxBytes-b.buffer.Len() {
		b.exceeded = true
		b.cancel()
		return 0, windowshardware.ErrBounds
	}
	return b.buffer.Write(p)
}

func unavailable(ctx context.Context, req windowshardware.Request, reason error) (windowshardware.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return windowshardware.Snapshot{}, err
	}
	return emptySnapshot(req, reason.Error()), nil
}

func emptySnapshot(req windowshardware.Request, reason string) windowshardware.Snapshot {
	return windowshardware.Empty(req, reason)
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
	resolve func(context.Context, windowshardware.Request) (windowshardware.Request, error),
	collectNative func(context.Context, windowshardware.Request) (windowshardware.Snapshot, error),
) error {
	if ctx == nil || in == nil || out == nil || resolve == nil || collectNative == nil {
		return windowshardware.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestBytes+1))
	if err != nil {
		return windowshardware.ErrInvalid
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
			return windowshardware.ErrInvalid
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
	if windowshardware.ValidateBinding(snapshot, req.GenerationID, req.Consent.GrantID, req.CollectedAt) != nil {
		return windowshardware.ErrInvalid
	}
	response, err := windowshardware.Encode(snapshot)
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
