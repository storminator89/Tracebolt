package main

import (
	"errors"
	"io"
	"os"
	"testing"
)

var errFreshConsoleOutput = errors.New("fresh console output unavailable")

// Test-only ownership scope. The native child supplies one newly opened CONOUT$
// writer; the original Go/Win32 standard handles are never changed or closed.
// The callback includes public display, hidden-input prompt and success marker.
func withFreshConsoleOutput(open func() (io.WriteCloser, error), character, console func(io.WriteCloser) error, run func(io.Writer) error) (err error) {
	if open == nil || character == nil || console == nil || run == nil {
		return errFreshConsoleOutput
	}
	output, openErr := open()
	if output != nil {
		defer func() {
			if closeErr := output.Close(); closeErr != nil && err == nil {
				err = errFreshConsoleOutput
			}
		}()
	}
	if openErr != nil || output == nil {
		return errFreshConsoleOutput
	}
	if character(output) != nil || console(output) != nil {
		return errFreshConsoleOutput
	}
	return run(output)
}

type freshOutputFixture struct {
	closed               int
	closeErr, errorWrite error
	text                 []byte
}

func (f *freshOutputFixture) Write(p []byte) (int, error) {
	if f.closed != 0 {
		return 0, errFreshConsoleOutput
	}
	if f.errorWrite != nil {
		return 0, f.errorWrite
	}
	f.text = append(f.text, p...)
	return len(p), nil
}
func (f *freshOutputFixture) Close() error { f.closed++; return f.closeErr }

func TestFreshConsoleOutputOwnershipAndFaults(t *testing.T) {
	private := errors.New("PRIVATE_SENTINEL")
	originalOut, originalErr := os.Stdout, os.Stderr
	defer func() {
		if os.Stdout != originalOut || os.Stderr != originalErr {
			t.Fatal("original standard writers changed")
		}
	}()
	for _, stage := range []string{"success", "open", "open_partial", "nil", "character", "console", "run", "write", "close", "run_close", "panic"} {
		t.Run(stage, func(t *testing.T) {
			f := &freshOutputFixture{}
			if stage == "close" || stage == "run_close" {
				f.closeErr = private
			}
			if stage == "write" {
				f.errorWrite = private
			}
			checks, runs := 0, 0
			open := func() (io.WriteCloser, error) {
				if stage == "open" {
					return nil, private
				}
				if stage == "open_partial" {
					return f, private
				}
				if stage == "nil" {
					return nil, nil
				}
				return f, nil
			}
			character := func(w io.WriteCloser) error {
				checks++
				if w != f {
					t.Fatal("different owned output")
				}
				if stage == "character" {
					return private
				}
				return nil
			}
			console := func(w io.WriteCloser) error {
				checks++
				if stage == "console" {
					return private
				}
				return nil
			}
			run := func(w io.Writer) error {
				runs++
				if f.closed != 0 {
					t.Fatal("closed before child work")
				}
				if stage == "panic" {
					panic(private)
				}
				if stage == "run" || stage == "run_close" {
					return private
				}
				for _, part := range []string{"public display\n", "public prompt", "\npublic marker\n"} {
					if _, err := io.WriteString(w, part); err != nil {
						return err
					}
				}
				return nil
			}
			var err error
			panicked := false
			func() {
				defer func() {
					if recover() != nil {
						panicked = true
					}
				}()
				err = withFreshConsoleOutput(open, character, console, run)
			}()
			expectClosed := 1
			if stage == "open" || stage == "nil" {
				expectClosed = 0
			}
			if f.closed != expectClosed {
				t.Fatal("owned output not closed exactly once")
			}
			if panicked != (stage == "panic") {
				t.Fatal("panic boundary changed")
			}
			if stage == "success" {
				if err != nil || runs != 1 || checks != 2 || string(f.text) != "public display\npublic prompt\npublic marker\n" {
					t.Fatal("public lifecycle not on one owned writer")
				}
			} else if stage != "panic" && err == nil {
				t.Fatal("failure accepted")
			}
			if stage == "open" || stage == "open_partial" || stage == "nil" || stage == "character" || stage == "console" {
				if runs != 0 {
					t.Fatal("child work before output validation")
				}
			}
			if stage == "run_close" && err != private {
				t.Fatal("first child failure lost")
			}
			if stage == "open" || stage == "open_partial" || stage == "nil" || stage == "character" || stage == "console" || stage == "close" {
				if err != errFreshConsoleOutput {
					t.Fatal("raw output setup error escaped")
				}
			}
		})
	}
}

func TestFreshConsoleOutputRejectsMissingCallbacks(t *testing.T) {
	open := func() (io.WriteCloser, error) { t.Fatal("opened before callback admission"); return nil, nil }
	check := func(io.WriteCloser) error { return nil }
	run := func(io.Writer) error { return nil }
	for _, err := range []error{
		withFreshConsoleOutput(nil, check, check, run),
		withFreshConsoleOutput(open, nil, check, run),
		withFreshConsoleOutput(open, check, nil, run),
		withFreshConsoleOutput(open, check, check, nil),
	} {
		if err != errFreshConsoleOutput {
			t.Fatal("incomplete output scope admitted")
		}
	}
}
