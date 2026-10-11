package windowshistoryworker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The only child here is this test executable, using invented request metadata.
// It neither opens Windows logs nor grants access or executes a shell.
func TestHistoryWorkerProcessFixture(t *testing.T) {
	mode := ""
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "history-fixture:") {
			mode = strings.TrimPrefix(arg, "history-fixture:")
		}
	}
	switch mode {
	case "blocked":
		time.Sleep(30 * time.Second)
		os.Exit(90)
	case "overflow":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
		os.Exit(0)
	case "secret-error":
		_, _ = os.Stderr.Write([]byte("private synthetic failure"))
		os.Exit(3)
	}
}
func TestOwnedHistoryWorkerBudgetOverflowAndErrorReap(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want error
	}{{"blocked", ErrBudget}, {"overflow", ErrBounds}, {"secret-error", ErrUnavailable}} {
		t.Run(tc.mode, func(t *testing.T) {
			var child *exec.Cmd
			budget := 3 * time.Second
			if tc.mode == "blocked" {
				budget = 250 * time.Millisecond
			}
			report, err := gather(context.Background(), workerFixture(t), budget, func(ctx context.Context) (*exec.Cmd, error) {
				child = exec.CommandContext(ctx, executable, "-test.run=^TestHistoryWorkerProcessFixture$", "--", "history-fixture:"+tc.mode)
				return child, nil
			})
			if !errors.Is(err, tc.want) || report.Source != "" || child == nil || child.Process == nil || child.ProcessState == nil {
				t.Fatal("worker did not fail closed and synchronously reap")
			}
			available := false
			if child.Process.WithHandle(func(uintptr) { available = true }) == nil || available {
				t.Fatal("worker retained process handle after wait")
			}
		})
	}
}
