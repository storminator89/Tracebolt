package main

import (
	"encoding/json"
	"fmt"
	"io"
	"localrmm/internal/lanclient"
)

type journalConsentOptions struct {
	Path, Mode, Identity    string
	Acknowledged, Plaintext bool
}
type journalConsentHooks struct {
	identity  func(string) bool
	configure func(string, string, bool, bool) (lanclient.JournalConsentResult, error)
}

func runJournalConsent(o journalConsentOptions, h journalConsentHooks, out, errOut io.Writer) int {
	if o.Path == "" || o.Identity == "" || o.Mode != "preview" && o.Mode != "initialize" || o.Acknowledged != (o.Mode == "initialize") || o.Mode == "preview" && o.Plaintext || h.identity == nil || h.configure == nil {
		fmt.Fprintln(errOut, "Journal consent requires preview or initialize with the existing service identity; initialize requires --ack-journal-content and HTTP additionally requires --ack-journal-http-plaintext. No collection or network occurs.")
		return 2
	}
	if !h.identity(o.Identity) {
		fmt.Fprintln(errOut, "Journal consent service identity rejected before private-state access.")
		return 2
	}
	result, e := h.configure(o.Path, o.Mode, o.Acknowledged, o.Plaintext)
	if e != nil {
		fmt.Fprintln(errOut, "Journal consent was not confirmed. Stop the sender and verify existing v3 handoff, ledgers and protected local policy. Existing state is never reset or repaired.")
		return 2
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	return 0
}
