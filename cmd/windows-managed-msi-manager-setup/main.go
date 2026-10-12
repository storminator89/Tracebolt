// windows-managed-msi-manager-setup prepares and finalizes an explicitly reviewed,
// create-only managed MSI software domain. It never starts any runtime.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"localrmm/internal/windowsmanagedmsimanager"
)

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "prepare" && args[0] != "finalize" {
		return windowsmanagedmsimanager.ErrSetup
	}
	flags := flag.NewFlagSet("windows-managed-msi-manager-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lan := flags.String("lan-config", "", "Existing protected TLS LAN config; never modified")
	en := flags.String("enrollment-config", "", "Existing protected guided enrollment config")
	device := flags.String("device-id", "", "Exact already activated Windows identity")
	expires := flags.Int64("expires-at", 0, "Fixed absolute consent expiry, Unix seconds; prepare only")
	registration := flags.String("registration-file", "", "Protected public Windows setup registration; finalize only")
	fleet := flags.Bool("fleet", false, "Create fresh upload-once fleet v2; never adopts singleton v1")
	reusable := flags.Bool("reusable-jobs", false, "Fresh v3 repeated separately approved jobs under original expiry; requires --fleet and coordinated endpoint setup")
	scheduled := flags.Bool("scheduled-jobs", false, "Fresh v4 explicitly approved UTC MSI windows; requires --fleet --reusable-jobs and paired background endpoint setup")
	additional := flags.Bool("additional-device", false, "Add one explicitly configured fleet target using the existing fleet key")
	apply := flags.Bool("apply", false, "Explicitly apply this create-only phase")
	approve := flags.String("approve-plan", "", "Exact reviewed public plan digest")
	acknowledge := flags.Bool("ack-managed-msi-delivery-install", false, "Approve the reviewed key preparation or reciprocal persistent managed MSI software authority; each actual install still requires separate named approval")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *scheduled && (!*fleet || !*reusable) || *lan == "" || *en == "" || *device == "" || !*apply && (*approve != "" || *acknowledge) || *apply && (*approve == "" || !*acknowledge) {
		return windowsmanagedmsimanager.ErrSetup
	}
	request := windowsmanagedmsimanager.SetupRequest{Scheduled: *scheduled, Reusable: *reusable, Fleet: *fleet, AdditionalDevice: *additional, Phase: args[0], LANConfig: *lan, EnrollmentConfig: *en, DeviceID: *device, ExpiresAt: *expires, RegistrationFile: *registration}
	plan, e := windowsmanagedmsimanager.PlanSetup(context.Background(), request, time.Now().UTC())
	if e != nil {
		return windowsmanagedmsimanager.ErrSetup
	}
	if !*apply {
		return json.NewEncoder(out).Encode(plan)
	}
	offer, e := windowsmanagedmsimanager.ApplySetup(context.Background(), plan, *approve, time.Now)
	if e != nil {
		return windowsmanagedmsimanager.ErrSetup
	}
	if offer != nil {
		return json.NewEncoder(out).Encode(offer)
	}
	notice := "Created one exact manager/device managed-MSI domain. The original LAN config is unchanged. No listener, endpoint launch, scan or install was started. Preserve all setup files and the enrollment database."
	return json.NewEncoder(out).Encode(struct {
		Version   string `json:"version"`
		Status    string `json:"status"`
		LANConfig string `json:"lanConfig"`
		Notice    string `json:"notice"`
	}{plan.Version, "created", windowsmanagedmsimanager.SetupPlanLANPath(plan), notice})
}
func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "Prepared MSI setup blocked. Preserve existing files, keys, started fences, receipts and ledgers; do not rerun or remove partial state.")
		os.Exit(1)
	}
}
