// windows-user-software is an explicitly invoked, one-capture console helper.
// It has no persistent mode, elevation request, account argument or unattended yes.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"localrmm/internal/windowsusersoftware"
	"localrmm/internal/windowsusersoftwarelocal"
	"os"
	"os/signal"
	"strings"
)

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: windows-user-software (run once in your own normal, non-elevated Windows console)")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	e := windowsusersoftwarelocal.RunForeground(ctx, func(ctx context.Context, ch windowsusersoftwarelocal.Challenge) bool {
		fmt.Printf("Selected-account software capture\nDevice: %q\nAccount context: %q\nSend to: %q\n\n%s\n", ch.DeviceID, ch.AccountLabel, ch.ManagerOrigin, windowsusersoftware.Privacy)
		if ch.InsecureHTTP {
			fmt.Printf("\n%s\n", windowsusersoftware.HTTPPrivacy)
		}
		fmt.Print("\nType CAPTURE to approve this one foreground read and send, or Enter to cancel: ")
		answer := make(chan string, 1)
		go func() {
			reader := bufio.NewReaderSize(os.Stdin, 128)
			line, e := reader.ReadSlice('\n')
			if e != nil || len(line) > 128 {
				answer <- ""
				return
			}
			answer <- strings.TrimSpace(string(line))
		}()
		select {
		case <-ctx.Done():
			return false
		case s := <-answer:
			return s == "CAPTURE"
		}
	})
	if errors.Is(e, windowsusersoftwarelocal.ErrDeclined) {
		fmt.Println("Capture canceled. No software registrations were read.")
		return 0
	}
	if e != nil {
		fmt.Fprintf(os.Stderr, "Capture was not confirmed: %v. The separate scope must be enabled, the fixed observation service must be live, and both OS peer/token checks must succeed. No automatic retry.\n", e)
		return 1
	}
	fmt.Println("The observation agent accepted this capture. Its original source status and capture time will be sent to the configured manager.")
	return 0
}
