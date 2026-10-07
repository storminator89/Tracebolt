// Package windowsconsole reads one invitation from the local Windows console.
// It has no argument, environment, file, redirected-input or logging interface.
package windowsconsole

import (
	"context"
	"errors"
	"time"
)

// ErrInput is the only error returned by ReadInvitation. Native errors, prompt
// errors and partial invitation material are never included in diagnostics.
var ErrInput = errors.New("hidden console invitation input unavailable or invalid")

const (
	invitationLength = 43
	pollInterval     = 25 * time.Millisecond
	processedInput   = uint32(0x0001)
	lineInput        = uint32(0x0002)
	echoInput        = uint32(0x0004)
	quickEdit        = uint32(0x0040)
	extendedFlags    = uint32(0x0080)
	virtualInput     = uint32(0x0200)
)

// A single process must not overlap console mode changes. Acquiring this gate
// observes cancellation, unlike a mutex held while a human enters input.
var consoleGate = make(chan struct{}, 1)

// ReadInvitation reads exactly one canonical 43-character base64url invitation
// from CONIN$, with echo disabled before invoking prompt. It never reads stdin.
// The caller owns and must clear the returned encoded bytes after use. prompt
// must write only public text and return promptly; it must not read input.
//
// Cancellation is checked between nonblocking native reads and bounded waits.
// Every ordinary exit restores and verifies the original console mode; failed
// restoration discards the result. Abrupt process/console termination cannot be
// repaired by a defer. Non-Windows systems fail without invoking prompt.
func ReadInvitation(ctx context.Context, prompt func() error) ([]byte, error) {
	if ctx == nil || prompt == nil || ctx.Err() != nil {
		return nil, ErrInput
	}
	select {
	case consoleGate <- struct{}{}:
		defer func() { <-consoleGate }()
	case <-ctx.Done():
		return nil, ErrInput
	}
	return readWithConsole(ctx, prompt, openConsole)
}

type console interface {
	mode() (uint32, error)
	setMode(uint32) error
	readRecord() (inputRecord, bool, error) // Must not wait for input.
	discard() error
	close() error
}

func hiddenMode(original uint32) uint32 {
	// Disable processed input so Ctrl+C is a record and can restore through the
	// same cleanup path. Extended flags are required to disable Quick Edit.
	return (original | extendedFlags) &^ (echoInput | lineInput | processedInput | quickEdit | virtualInput)
}

func restoreMode(c console, original uint32) error {
	// Extended flags must be present while restoring the Quick Edit bit. Then
	// restore the exact original mask, including an originally unset flag.
	if c.setMode(original|extendedFlags) != nil {
		return ErrInput
	}
	if original&extendedFlags == 0 && c.setMode(original) != nil {
		return ErrInput
	}
	actual, err := c.mode()
	if err != nil || actual != original {
		return ErrInput
	}
	return nil
}

func readWithConsole(ctx context.Context, prompt func() error, open func() (console, error)) (secret []byte, err error) {
	if ctx == nil || prompt == nil || ctx.Err() != nil {
		return nil, ErrInput
	}
	c, err := open()
	if err != nil || c == nil {
		return nil, ErrInput
	}
	var original uint32
	var modeAttempted bool
	var decoder invitationDecoder
	defer func() {
		decoder.clear()
		failed := false
		if modeAttempted {
			// Discard unread paste suffixes before restoring echo. This also
			// clears pending input on cancellation or invalid input.
			if c.discard() != nil {
				failed = true
			}
			if restoreMode(c, original) != nil {
				failed = true
			}
		}
		if c.close() != nil {
			failed = true
		}
		if failed || err != nil || ctx.Err() != nil {
			clear(secret)
			secret, err = nil, ErrInput
		}
	}()
	original, err = c.mode()
	if err != nil {
		return nil, ErrInput
	}
	modeAttempted = true // Even a failed mode change must attempt restoration.
	if c.setMode(hiddenMode(original)) != nil {
		return nil, ErrInput
	}
	actual, err := c.mode()
	if err != nil || actual != hiddenMode(original) {
		return nil, ErrInput
	}
	// Do not accept type-ahead that predates the hidden prompt.
	if c.discard() != nil || ctx.Err() != nil || prompt() != nil {
		return nil, ErrInput
	}
	for {
		if ctx.Err() != nil {
			return nil, ErrInput
		}
		record, available, readErr := c.readRecord()
		if readErr != nil {
			record.clear()
			return nil, ErrInput
		}
		if available {
			done, decodeErr := decoder.consume(record)
			record.clear()
			if decodeErr != nil {
				return nil, ErrInput
			}
			if done {
				return decoder.take(), nil
			}
			continue
		}
		record.clear()
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ErrInput
		case <-timer.C:
		}
	}
}
