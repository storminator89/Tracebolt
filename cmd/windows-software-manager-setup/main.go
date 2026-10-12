// windows-software-manager-setup prepares and finalizes an explicitly reviewed,
// create-only prepared MSI software domain. It never starts any runtime.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"localrmm/internal/windowssoftwaremanager"
)

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "prepare" && args[0] != "finalize" {
		return windowssoftwaremanager.ErrSetup
	}
	flags := flag.NewFlagSet("windows-software-manager-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lan := flags.String("lan-config", "", "Existing protected TLS LAN config; never modified")
	en := flags.String("enrollment-config", "", "Existing protected guided enrollment config")
	device := flags.String("device-id", "", "Exact already activated Windows identity")
	expires := flags.Int64("expires-at", 0, "Fixed absolute consent expiry, Unix seconds; prepare only")
	registration := flags.String("registration-file", "", "Protected public Windows setup registration; finalize only")
	additional := flags.Bool("additional-device", false, "Create a new exact device grant using the activated complete manager software registry and its existing purpose-specific key")
	apply := flags.Bool("apply", false, "Explicitly apply this create-only phase")
	approve := flags.String("approve-plan", "", "Exact reviewed public plan digest")
	acknowledge := flags.Bool("ack-prepared-msi-install", false, "Approve the reviewed key preparation or reciprocal persistent prepared MSI software authority; each actual install still requires separate named approval")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *lan == "" || *en == "" || *device == "" || !*apply && (*approve != "" || *acknowledge) || *apply && (*approve == "" || !*acknowledge) {
		return windowssoftwaremanager.ErrSetup
	}
	request := windowssoftwaremanager.SetupRequest{Phase: args[0], LANConfig: *lan, EnrollmentConfig: *en, DeviceID: *device, ExpiresAt: *expires, RegistrationFile: *registration, AdditionalDevice: *additional}
	plan, e := windowssoftwaremanager.PlanSetup(context.Background(), request, time.Now().UTC())
	if e != nil {
		return windowssoftwaremanager.ErrSetup
	}
	if !*apply {
		return json.NewEncoder(out).Encode(plan)
	}
	offer, e := windowssoftwaremanager.ApplySetup(context.Background(), plan, *approve, time.Now)
	if e != nil {
		return windowssoftwaremanager.ErrSetup
	}
	if offer != nil {
		return json.NewEncoder(out).Encode(offer)
	}
	notice := "Created one exact manager/device prepared-MSI domain. The original LAN config is unchanged. No listener, endpoint launch, scan or install was started. Preserve all setup files and the enrollment database."
	if plan.Request.AdditionalDevice {
		notice = "Created one additional exact device registration and staged a new explicit registry/LAN config. Original configurations, key, receipts and device history are unchanged. Registry activation, endpoint launch and each installation require separate approval. Preserve all setup files and the enrollment database."
	}
	return json.NewEncoder(out).Encode(struct {
		Version   string `json:"version"`
		Status    string `json:"status"`
		LANConfig string `json:"lanConfig"`
		Notice    string `json:"notice"`
	}{plan.Version, "created", windowssoftwaremanager.SetupPlanLANPath(plan), notice})
}
func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "Prepared MSI setup blocked. Preserve existing files, keys, started fences, receipts and ledgers; do not rerun or remove partial state.")
		os.Exit(1)
	}
}
