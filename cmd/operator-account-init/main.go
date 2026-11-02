// operator-account-init prepares an explicitly approved, create-only live account
// journal and reference. It never edits existing configuration or starts services.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

type options struct {
	lanConfig, output string
	runtimeUID        int
	acknowledge       bool
}
type result struct {
	Version  string `json:"version"`
	OK       bool   `json:"ok"`
	Created  bool   `json:"created"`
	Code     string `json:"code"`
	NextStep string `json:"nextStep"`
}

func report(out io.Writer, ok bool, code, next string) int {
	if json.NewEncoder(out).Encode(result{"tracebolt.operator-account-init.v1", ok, ok, code, next}) != nil {
		return 1
	}
	if !ok {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
func run(args []string, out io.Writer) int {
	f := flag.NewFlagSet("operator-account-init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	o := options{runtimeUID: -1}
	f.StringVar(&o.lanConfig, "lan-config", "", "existing protected TLS LAN configuration")
	f.StringVar(&o.output, "output", "", "new protected v3 operator-auth reference outside state/frontend")
	f.IntVar(&o.runtimeUID, "runtime-uid", -1, "explicit nonroot manager UID")
	f.BoolVar(&o.acknowledge, "acknowledge-live-authority", false, "acknowledge permanent create-only live-authority fence and provided named credentials")
	err := f.Parse(args)
	if err == flag.ErrHelp {
		fmt.Fprintln(out, "Usage: operator-account-init --lan-config ABSOLUTE_EXISTING_FILE --output ABSOLUTE_NEW_FILE --runtime-uid UID --acknowledge-live-authority")
		fmt.Fprintln(out, "Linux-only; source must be protected named-v2 TLS auth with an explicit manage_accounts grant. Requires preexisting private state/output directories and stopped manager. Creates a permanent used marker, protected account journal and new v3 reference; never overwrites or deletes existing state. A failed or uncertain result requires reviewed recovery, not automatic retry. It does not activate live mode or modify the existing LAN configuration. No passwords/verifiers/private keys in arguments.")
		return 0
	}
	if err != nil || f.NArg() != 0 || o.runtimeUID <= 0 || o.lanConfig == "" || o.output == "" || !o.acknowledge {
		return report(out, false, "arguments", "Review --help and explicit approval; argument values were not echoed.")
	}
	code := initialize(o)
	if code != "created" {
		return report(out, false, code, "Preserve all files and stop dependent startup. Review protected paths, existing authority and any retained partial state locally; never delete, overwrite or blindly retry.")
	}
	return report(out, true, code, "Live authority was provisioned but not activated. Under the reviewed configuration change, select the new v3 operator-auth reference in the LAN configuration, then start the matching manager. Existing approvals without an account epoch remain blocked in live mode.")
}
