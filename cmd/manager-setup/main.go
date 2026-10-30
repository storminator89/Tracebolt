// manager-setup is a read-only guided-TLS doctor and create-only LAN config writer.
// It does not generate/import credentials, initialize databases or start services.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/lanconfig"
	"localrmm/internal/managersetup"
	"os"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: manager-setup doctor --lan-config ABSOLUTE_FILE --enrollment-config ABSOLUTE_FILE --runtime-uid UID [--require-windows]")
	fmt.Fprintln(out, "       manager-setup init --output ABSOLUTE_NEW_FILE --runtime-uid UID --enrollment-config ABSOLUTE_FILE --ack-provisioned-material --operator-origin HTTPS_ORIGIN --agent-origin HTTPS_ORIGIN --tls-certificate ABSOLUTE_FILE --tls-private-key ABSOLUTE_FILE --agent-client-ca ABSOLUTE_FILE --operator-auth ABSOLUTE_FILE --state-directory ABSOLUTE_EMPTY_DIR --web-directory ABSOLUTE_DIR [--operator-listen 127.0.0.1:8443] [--agent-listen 127.0.0.1:8444] [--windows-inventory]")
	fmt.Fprintln(out, "Linux-only; run as the explicit nonroot manager UID, in the intended filesystem/network namespace. JSON diagnostics never echo input values. Init creates only a new private LAN config; all approved credentials/trust/issuer configuration and protected directories must already exist. Root CA private keys stay offline. No host, service, database, mode-marker, credential or trust-store changes are made.")
}

func emit(out io.Writer, r managersetup.Report) int {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if enc.Encode(r) != nil {
		return 1
	}
	if !r.OK {
		return 1
	}
	return 0
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		return emit(out, managersetup.Failure("arguments", "usage", "No operation was selected.", "Use manager-setup --help; select doctor or init."))
	}
	if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		usage(out)
		return 0
	}
	operation := args[0]
	if operation != "doctor" && operation != "init" {
		return emit(out, managersetup.Failure("arguments", "usage", "Unknown operation.", "Use manager-setup --help; only doctor and init are supported."))
	}
	f := flag.NewFlagSet("manager-setup", flag.ContinueOnError)
	// flag errors normally echo input, including accidental sensitive arguments.
	// Emit static structured diagnostics instead; no raw parser/error text escapes.
	f.SetOutput(io.Discard)
	uid := f.Int("runtime-uid", -1, "explicit nonroot runtime UID")
	enrollment := f.String("enrollment-config", "", "absolute existing protected issuer config")
	var path, output string
	var ack, requireWindows bool
	c := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.TLS}
	if operation == "doctor" {
		f.StringVar(&path, "lan-config", "", "absolute protected LAN config")
		f.BoolVar(&requireWindows, "require-windows", false, "require explicit Windows inventory profile")
	} else {
		f.StringVar(&output, "output", "", "absolute new protected LAN config")
		f.BoolVar(&ack, "ack-provisioned-material", false, "acknowledge approved preprovisioned credential/trust custody and create-only config write")
		f.StringVar(&c.OperatorOrigin, "operator-origin", "", "exact canonical HTTPS operator origin")
		f.StringVar(&c.AgentOrigin, "agent-origin", "", "exact canonical HTTPS agent origin")
		f.StringVar(&c.OperatorListen, "operator-listen", "127.0.0.1:8443", "approved literal-IP operator bind")
		f.StringVar(&c.AgentListen, "agent-listen", "127.0.0.1:8444", "approved literal-IP agent bind")
		f.StringVar(&c.TLSCertificateFile, "tls-certificate", "", "approved protected public server chain")
		f.StringVar(&c.TLSPrivateKeyFile, "tls-private-key", "", "approved protected server key path, never key contents")
		f.StringVar(&c.AgentClientCAFile, "agent-client-ca", "", "approved dedicated client-auth intermediate")
		f.StringVar(&c.OperatorAuthFile, "operator-auth", "", "approved protected operator verifier file")
		f.StringVar(&c.StateDirectory, "state-directory", "", "existing empty private state directory")
		f.StringVar(&c.WebDirectory, "web-directory", "", "matching protected frontend directory")
		f.BoolVar(&c.WindowsInventoryEnabled, "windows-inventory", false, "explicit fresh Windows inventory enrollment opt-in, not endpoint scope consent")
	}
	if err := f.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			usage(out)
			return 0
		}
		return emit(out, managersetup.Failure(operation, "arguments", "Arguments could not be parsed; values were not echoed.", "Review manager-setup --help. Supply paths only, never passwords, invitations, verifier values or private-key contents."))
	}
	if f.NArg() != 0 || *uid <= 0 || (operation == "doctor" && path == "") || (operation == "init" && (output == "" || !ack)) {
		return emit(out, managersetup.Failure(operation, "arguments", "Required explicit arguments or provisioning acknowledgement are missing.", "Review manager-setup --help. Init requires the approved material acknowledgement and new output; both commands require the intended nonroot --runtime-uid."))
	}
	options := managersetup.Options{ExpectedUID: *uid, EnrollmentConfig: *enrollment, RequireWindows: requireWindows}
	if operation == "doctor" {
		return emit(out, managersetup.Doctor(path, options, time.Now().UTC()))
	}
	return emit(out, managersetup.Initialize(c, output, options, time.Now().UTC()))
}
