// http-test-setup provisions only disposable HTTP-test material, never a server.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
)

const outputDirectory = "/etc/tracebolt-http-test"
const outputName = "tracebolt-http-test"
const usage = "Usage: http-test-setup --lan-ip <private-IPv4> --ack-disposable-http-test [--apply]\nDefault: print a plan only. Linux apply requires root and a controlling terminal.\n"

type options struct {
	ip                 string
	acknowledge, apply bool
}

// All injection is package-private and unavailable through flags or environment.
type dependencies struct {
	root       func() bool
	prompt     func(context.Context) ([]byte, error)
	openParent func() (int, error)
	random     io.Reader
	now        func() time.Time
	uid, gid   int
}

func run(ctx context.Context, args []string, out io.Writer, d dependencies) int {
	fail := func(stage string) int { fmt.Fprintln(out, "HTTP-test setup failed:", stage); return 1 }
	fs := flag.NewFlagSet("http-test-setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // Never echo unknown arguments or their values.
	var o options
	fs.StringVar(&o.ip, "lan-ip", "", "selected private LAN IPv4")
	fs.BoolVar(&o.acknowledge, "ack-disposable-http-test", false, "acknowledge disposable plaintext test")
	fs.BoolVar(&o.apply, "apply", false, "create the fixed new directory")
	if e := fs.Parse(args); e != nil {
		if e == flag.ErrHelp {
			fmt.Fprint(out, usage)
			return 0
		}
		return fail("arguments")
	}
	if fs.NArg() != 0 || !validIP(o.ip) {
		return fail("arguments")
	}
	if _, e := fmt.Fprintf(out, "Disposable HTTP-test plan (unencrypted passwords, sessions and telemetry):\nOperator origin: http://%s:8787\nAgent origin: http://%s:8788\nContainer listeners: 0.0.0.0:8787 and 0.0.0.0:8788; host publication must use the selected LAN IP.\nCreate only: %s (0700), six files (0600), Docker UID/GID 65532:65532.\nDedicated 30-day client-auth issuer; root private key is memory-only and discarded.\nNo server, listener, service, account, trust, firewall, invitation or endpoint changes.\n", o.ip, o.ip, outputDirectory); e != nil {
		return 1
	}
	if !o.apply {
		return 0
	}
	if !o.acknowledge {
		return fail("disposable HTTP acknowledgement required")
	}
	if d.root == nil || !d.root() {
		return fail("root required")
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	parent, e := d.openParent()
	if e != nil {
		return fail("protected parent or existing output")
	}
	defer closeParent(parent)
	if e = outputAbsent(parent); e != nil {
		return fail("protected parent or existing output")
	}
	password, e := d.prompt(ctx)
	defer clear(password)
	if e != nil || !validPassword(password) {
		return fail("terminal password confirmation")
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	files, e := generate(o.ip, password, d.random, d.now().UTC())
	clear(password)
	if e != nil {
		return fail("material generation or validation")
	}
	defer clearFiles(files)
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	if e = publish(ctx, parent, files, d.uid, d.gid); e != nil {
		return fail("publication; inspect fixed output before retry")
	}
	fmt.Fprintln(out, "HTTP-test setup complete:", outputDirectory+"/http-test.json")
	return 0
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), platformSignals()...)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, dependencies{root: func() bool { return os.Getuid() == 0 && os.Geteuid() == 0 }, prompt: readPassword, openParent: openProtectedParent, random: rand.Reader, now: time.Now, uid: 65532, gid: 65532}))
}
