// windows-update-manager-setup prepares and finalizes an explicitly reviewed,
// create-only selected Windows update domain. It never starts any runtime.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"localrmm/internal/windowsupdatemanager"
)

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "prepare" && args[0] != "finalize" {
		return windowsupdatemanager.ErrSetup
	}
	flags := flag.NewFlagSet("windows-update-manager-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lan := flags.String("lan-config", "", "Existing protected TLS LAN config; never modified")
	en := flags.String("enrollment-config", "", "Existing protected guided enrollment config")
	device := flags.String("device-id", "", "Exact already activated Windows identity")
	expires := flags.Int64("expires-at", 0, "Fixed absolute consent expiry, Unix seconds; prepare only")
	registration := flags.String("registration-file", "", "Protected public Windows setup registration; finalize only")
	additional := flags.Bool("additional-device", false, "Create a new exact device grant using the activated complete manager update registry and its existing purpose-specific key")
	apply := flags.Bool("apply", false, "Explicitly apply this create-only phase")
	approve := flags.String("approve-plan", "", "Exact reviewed public plan digest")
	acknowledge := flags.Bool("ack-selected-windows-update-install", false, "Approve the reviewed key preparation or reciprocal persistent selected update authority; each actual install still requires separate named approval")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *lan == "" || *en == "" || *device == "" || !*apply && (*approve != "" || *acknowledge) || *apply && (*approve == "" || !*acknowledge) {
		return windowsupdatemanager.ErrSetup
	}
	request := windowsupdatemanager.SetupRequest{Phase: args[0], LANConfig: *lan, EnrollmentConfig: *en, DeviceID: *device, ExpiresAt: *expires, RegistrationFile: *registration, AdditionalDevice: *additional}
	plan, e := windowsupdatemanager.PlanSetup(context.Background(), request, time.Now().UTC())
	if e != nil {
		return windowsupdatemanager.ErrSetup
	}
	if !*apply {
		return json.NewEncoder(out).Encode(plan)
	}
	offer, e := windowsupdatemanager.ApplySetup(context.Background(), plan, *approve, time.Now)
	if e != nil {
		return windowsupdatemanager.ErrSetup
	}
	if offer != nil {
		return json.NewEncoder(out).Encode(offer)
	}
	notice := "Created one exact manager/device update domain. The original LAN config is unchanged. No listener, endpoint launch, scan or install was started. Preserve all setup files and the enrollment database."
	if plan.Request.AdditionalDevice {
		notice = "Created one additional exact device registration and staged a new explicit registry/LAN config. Original configurations, key, receipts and device history are unchanged. Registry activation, endpoint launch and each installation require separate approval. Preserve all setup files and the enrollment database."
	}
	return json.NewEncoder(out).Encode(struct {
		Version   string `json:"version"`
		Status    string `json:"status"`
		LANConfig string `json:"lanConfig"`
		Notice    string `json:"notice"`
	}{plan.Version, "created", windowsupdatemanager.SetupPlanLANPath(plan), notice})
}
func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "Selected Windows update setup blocked. Preserve existing files, keys, started fences, receipts and ledgers; do not rerun or remove partial state.")
		os.Exit(1)
	}
}
