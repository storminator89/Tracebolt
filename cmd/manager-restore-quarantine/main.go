// manager-restore-quarantine installs or inspects a deny-only startup marker.
// It never copies/restores a backup, opens a database or releases authority.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/lanstore"
	"os"
	"runtime"
)

type report struct {
	SchemaVersion     string `json:"schemaVersion"`
	OK                bool   `json:"ok"`
	Code              string `json:"code"`
	MarkerPresent     *bool  `json:"markerPresent"`
	Created           bool   `json:"created"`
	FreshnessVerified bool   `json:"freshnessVerified"`
	AuthorityReleased bool   `json:"authorityReleased"`
	NextStep          string `json:"nextStep"`
}

// A nil presence is unknown, never an assertion that an uncertain marker is absent.
func presence(value bool) *bool { return &value }

func emit(out io.Writer, r report) int {
	r.SchemaVersion = "tracebolt.restore-quarantine-status.v1"
	if json.NewEncoder(out).Encode(r) != nil || !r.OK {
		return 1
	}
	return 0
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: manager-restore-quarantine mark --state-directory ABSOLUTE_EXISTING_PRIVATE_DIR --runtime-uid UID --ack-stopped-writers")
	fmt.Fprintln(out, "       manager-restore-quarantine status --state-directory ABSOLUTE_EXISTING_PRIVATE_DIR --runtime-uid UID")
	fmt.Fprintln(out, "Linux only. Run as the intended nonroot manager UID after stopping every writer and disabling all automatic/concurrent starts. Mark exclusively creates and syncs a deny-only marker; it does not stop an active manager, restore or validate a backup, change credentials or reconcile authority. No release/reset command exists. A missing marker never proves freshness.")
}

func run(args []string, out io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		usage(out)
		return 0
	}
	invalid := func() int {
		return emit(out, report{Code: "arguments_rejected", NextStep: "Review --help; use paths only, never credentials or backup contents. Mark requires acknowledgement that writers and automatic/concurrent starts are stopped."})
	}
	if len(args) == 0 || (args[0] != "mark" && args[0] != "status") {
		return invalid()
	}
	flags := flag.NewFlagSet("manager-restore-quarantine", flag.ContinueOnError)
	// Never echo accidental secret-bearing parser input or filesystem errors.
	flags.SetOutput(io.Discard)
	dir := flags.String("state-directory", "", "existing private state directory")
	uid := flags.Int("runtime-uid", -1, "explicit nonroot manager UID")
	var ack bool
	if args[0] == "mark" {
		flags.BoolVar(&ack, "ack-stopped-writers", false, "all manager writers and automatic/concurrent starts are stopped")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			usage(out)
			return 0
		}
		return invalid()
	}
	if flags.NArg() != 0 || *dir == "" || *uid <= 0 || (args[0] == "mark" && !ack) {
		return invalid()
	}
	if runtime.GOOS != "linux" || os.Geteuid() != *uid {
		return emit(out, report{Code: "runtime_uid_rejected", NextStep: "Run on Linux as the explicitly selected existing nonroot manager UID; do not change accounts or permissions to bypass this check."})
	}
	// Runtime startup allows a missing directory for an ordinary fresh profile;
	// this inspection/marking tool must instead name an existing restore target.
	info, statErr := os.Lstat(*dir)
	if statErr != nil || !info.IsDir() {
		return emit(out, report{Code: "state_path_rejected", NextStep: "Keep writers stopped. Select the existing original private state directory; this tool never creates directories."})
	}
	err := lanstore.CheckRestoreQuarantine(*dir)
	if errors.Is(err, lanstore.ErrRestoreQuarantined) {
		return emit(out, report{OK: true, Code: "quarantined", MarkerPresent: presence(true), NextStep: "Keep all manager writers stopped. Independently reconcile current revocations, consumed-action/replay floors and consent; no authority release is implemented."})
	}
	if err != nil {
		return emit(out, report{Code: "state_path_rejected", NextStep: "Keep writers stopped. Inspect the original protected state path and ownership locally; no file or permission was repaired."})
	}
	if args[0] == "status" {
		return emit(out, report{OK: true, Code: "marker_absent_not_freshness_proof", MarkerPresent: presence(false), NextStep: "Absence does not verify current authority or a backup. Before a restore, keep writers stopped and explicitly mark the restored state; do not reconnect endpoints."})
	}
	err = lanstore.MarkRestoreQuarantine(*dir)
	if err != nil {
		// Even if a concurrent creator won, no durability claim follows from
		// this failed write attempt. A later status only reports presence.
		return emit(out, report{Code: "mark_unconfirmed", NextStep: "Keep writers stopped. Inspect quarantine status and storage locally; retain every partial marker. Do not delete, overwrite or blindly retry uncertain writes."})
	}
	return emit(out, report{OK: true, Code: "quarantined", MarkerPresent: presence(true), Created: true, NextStep: "Marker creation was synced. Keep writers stopped; no backup integrity, freshness, reconciliation or authority release is established."})
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
