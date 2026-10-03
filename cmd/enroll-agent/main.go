// enroll-agent is the Linux guided enrollment client. It never installs a service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/enrollmentclient"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("enroll-agent", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	bootstrap := f.String("bootstrap", "", "Absolute public bootstrap JSON path")
	state := f.String("state-directory", "", "Absolute dedicated private enrollment directory")
	insecure := f.Bool("insecure-http-test", false, "Acknowledge visible invitations and unauthenticated HTTP test responses")
	timeout := f.Duration("timeout", 15*time.Minute, "Approval timeout, at most 30m")
	if f.Parse(args) != nil || f.NArg() != 0 || *bootstrap == "" || *state == "" {
		fmt.Fprintln(errOut, "Usage: enroll-agent --bootstrap ABS_PATH --state-directory ABS_PATH [--insecure-http-test] [--timeout 15m]. Invitation input is hidden; there is no invitation argument, environment or stdin mode.")
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(errOut, "Guided enrollment is currently Linux-only.")
		return 2
	}
	b, e := enrollmentclient.LoadBootstrap(*bootstrap)
	if e != nil {
		fmt.Fprintln(errOut, "Public bootstrap rejected. Obtain the exact trusted bootstrap from your manager.")
		return 2
	}
	lastPhase := ""
	result, e := enrollmentclient.Run(ctx, b, enrollmentclient.Options{StateDirectory: *state, InsecureHTTPAcknowledged: *insecure, Timeout: *timeout, Display: func(d enrollmentclient.TrustDisplay) error {
		if _, e := fmt.Fprintf(out, "Manager: %s\nProfile: %s\nEnrollment destination: %s\nAgent destination: %s\nCollection: %s\nInvitation: %s\n", d.ManagerInstanceID, d.Profile, d.EnrollmentOrigin, d.AgentOrigin, d.CollectionProfile, d.InvitationID); e != nil {
			return e
		}
		for _, fp := range d.ServerCAFingerprints {
			if _, e := fmt.Fprintf(out, "Server CA certificate SHA-256: %s\n", fp); e != nil {
				return e
			}
		}
		if _, e := fmt.Fprintf(out, "Issuer root certificate SHA-256: %s\nIssuer certificate SHA-256: %s\nLocal device SPKI SHA-256: %s\nLocal 128-bit comparison: %s\nCompare the complete local fingerprint and comparison value in the manager before approval.\n", d.IssuerRootFingerprint, d.IssuerFingerprint, d.KeyFingerprint, d.ComparisonCode); e != nil {
			return e
		}
		if d.HTTPTest {
			_, e := fmt.Fprintln(out, "WARNING: UNENCRYPTED HTTP TEST. Invitations and reports are visible. The manager and activation responses are NOT authenticated. Use disposable test material.")
			return e
		}
		return nil
	}, Secret: func(c context.Context) ([]byte, error) {
		secret, e := readInvitation(c, func() error {
			_, e := fmt.Fprint(errOut, "Verify the destinations and public trust above, then enter the invitation (hidden): ")
			return e
		})
		_, w := fmt.Fprintln(errOut)
		if e != nil {
			return nil, e
		}
		if w != nil {
			clear(secret)
			return nil, w
		}
		return secret, nil
	}, Notify: func(p enrollmentclient.Progress) error {
		if p.Phase == lastPhase {
			return nil
		}
		lastPhase = p.Phase
		text := ""
		switch p.Phase {
		case "pending_approval":
			text = "Waiting for approval in the manager. The key and operation are saved for safe resume."
		case "reconciling":
			text = "Checking the saved operation after an uncertain response."
		case "ready":
			text = "Enrollment handoff is ready."
		}
		_, e := fmt.Fprintln(out, text)
		return e
	}})
	if e != nil {
		if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			fmt.Fprintln(errOut, "Enrollment stopped. Keep the same bootstrap and state directory to resume; no key or state was reset.")
			return 1
		}
		// All package errors are fixed safe messages. Never print raw OS, response,
		// HTTP-provider, callback, path, proof, invitation or private-key values.
		text := "Enrollment could not finish. Keep the same private state and retry after checking the manager."
		switch {
		case errors.Is(e, enrollmentclient.ErrState):
			text = "Private enrollment state rejected. Preserve it for inspection; no cleanup or reset was performed."
		case errors.Is(e, enrollmentclient.ErrLocked):
			text = "Another enrollment process holds this state directory."
		case errors.Is(e, enrollmentclient.ErrTerminal):
			text = "The enrollment was canceled, rejected, revoked or expired. Preserve the local state; request a new authorized enrollment separately."
		case errors.Is(e, enrollmentclient.ErrInvitation):
			if b.Profile == "tls" {
				text = "Invitation rejected. Keep the same bootstrap and state directory, check the invitation, and rerun. A different invitation is accepted only after an authenticated definite rejection and status reconciliation."
			} else {
				text = "HTTP-test invitation rejected or different from the saved claim. Preserve this state. A wrong invitation may require the operator to cancel it and provide a new invitation for a NEW state directory."
			}
		case errors.Is(e, enrollmentclient.ErrBootstrap):
			text = "Bootstrap, flags or HTTP-test acknowledgement rejected."
		case errors.Is(e, enrollmentclient.ErrResponse):
			text = "Manager response did not match the locally bound enrollment contract."
		case errors.Is(e, enrollmentclient.ErrInput):
			text = "Hidden invitation input or output failed. Use a local terminal; no stdin or environment handoff is supported."
		}
		fmt.Fprintln(errOut, text)
		return 1
	}
	if !result.ServerAuthenticated {
		fmt.Fprintln(out, "WARNING: HTTP-test activation was reported by an unauthenticated manager. This is not verified server activation.")
	}
	if _, e = fmt.Fprintf(out, "To start regular read-only reporting in the foreground:\nlan-agent --config %s --foreground\nNo service was installed. Stopping this command stops reporting.\n", shellQuote(result.ConfigPath)); e != nil {
		return 1
	}
	return 0
}
func shellQuote(s string) string {
	r := "'"
	for _, c := range s {
		if c == '\'' {
			r += "'\"'\"'"
		} else {
			r += string(c)
		}
	}
	return r + "'"
}
