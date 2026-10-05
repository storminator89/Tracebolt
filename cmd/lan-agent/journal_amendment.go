package main

import (
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
)

type journalAmendmentOptions struct {
	Path, Mode, Identity    string
	Acknowledged, Plaintext bool
}
type journalAmendmentHooks struct {
	identity  func(string) bool
	configure func(string, string, bool, bool) (lanclient.JournalAmendmentResult, error)
}

func runJournalAmendment(o journalAmendmentOptions, h journalAmendmentHooks, out, errOut io.Writer) int {
	if o.Path == "" || o.Identity == "" || o.Mode != "preview" && o.Mode != "accept" || o.Acknowledged != (o.Mode == "accept") || o.Mode == "preview" && o.Plaintext || h.identity == nil || h.configure == nil {
		fmt.Fprintln(errOut, "Journal amendment requires preview or accept under the stopped service identity. Accept requires content acknowledgement and HTTP additionally requires plaintext acknowledgement. No source or network access occurs.")
		return 2
	}
	if !h.identity(o.Identity) {
		fmt.Fprintln(errOut, "Journal amendment identity rejected before private-state access.")
		return 2
	}
	r, e := h.configure(o.Path, o.Mode, o.Acknowledged, o.Plaintext)
	if e != nil {
		fmt.Fprintln(errOut, "Journal amendment was not confirmed. Preserve all existing state and transaction evidence; no automatic recovery is performed.")
		return 2
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 2
	}
	return 0
}
