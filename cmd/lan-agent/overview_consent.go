package main

import (
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
)

type overviewConsentOptions struct {
	Path, Mode, Identity string
	Acknowledged         bool
}
type overviewConsentHooks struct {
	identity  func(string) bool
	configure func(string, string, bool) (lanclient.OverviewConsentResult, error)
}

func runOverviewConsent(o overviewConsentOptions, h overviewConsentHooks, out, errOut io.Writer) int {
	if o.Path == "" || o.Identity == "" || o.Mode != "preview" && o.Mode != "enable" && o.Mode != "disable" || o.Acknowledged != (o.Mode == "enable") || h.identity == nil || h.configure == nil {
		fmt.Fprintln(errOut, "Complete overview consent requires exactly preview, enable, or disable; enable additionally requires --ack-complete-overview for full visible processes/mounts, potentially sensitive names, labels and Linux namespace scope at a fixed 60-second cadence. No collection or network occurs in this mode.")
		return 2
	}
	if !h.identity(o.Identity) {
		fmt.Fprintln(errOut, "Complete overview consent service identity rejected before private-state access.")
		return 2
	}
	result, e := h.configure(o.Path, o.Mode, o.Acknowledged)
	if e != nil {
		fmt.Fprintln(errOut, "Complete overview consent configuration was not confirmed. Stop the sender and check existing protected v3 handoff/state; existing ledgers are never reset; only a fresh complete-overview domain pair may be initialized.")
		return 2
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	if o.Mode == "disable" {
		fmt.Fprintln(errOut, "Local full process/mount collection and delivery are disabled. Retained unsent overview bytes remain dormant; independent consumed sequence floors and original capture ages are preserved. Previously delivered metadata keeps its original retention expiry.")
	}
	return 0
}
