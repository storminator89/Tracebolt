package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"strings"
	"testing"
)

func TestSetupHandoffPreservesExactOriginalAuthority(t *testing.T) {
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32)).Public().(ed25519.PublicKey)
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32)).Public().(ed25519.PublicKey)
	o := SetupOffer{SetupOfferVersion, "manager_" + strings.Repeat("1", 32), "agent_" + strings.Repeat("2", 32), actionpermit.Digest([]byte("anchor")), "https://manager.invalid", manager, 1800000300}
	r := SetupRegistration{SetupRegistrationVersion, o, Consent{ConsentVersion, Scope, Binding{o.ManagerID, o.DeviceID, o.IncarnationDigest, "executor_" + strings.Repeat("3", 32), actionpermit.Digest(executor), "grant_" + strings.Repeat("4", 32), actionpermit.Digest(manager)}, true, true, o.ExpiresAt, "", false}, executor}
	raw, _ := json.Marshal(r)
	if r.Validate() != nil {
		t.Fatal("valid fixture")
	}
	if _, e := DecodeSetupRegistration(raw); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*SetupRegistration){func(r *SetupRegistration) { r.Consent.ExpiresAt++ }, func(r *SetupRegistration) { r.Consent.Binding.ManagerID = "manager_" + strings.Repeat("5", 32) }, func(r *SetupRegistration) { r.Offer.ManagerOrigin = "http://manager.invalid" }, func(r *SetupRegistration) { r.ExecutorPublicKey = manager }, func(r *SetupRegistration) { r.Consent.Scope = "windows-observation" }} {
		v := r
		change(&v)
		if v.Validate() == nil {
			t.Fatal("handoff widened authority")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":0,"version":`), 1), append(bytes.Clone(raw), raw...)} {
		if _, e := DecodeSetupRegistration(bad); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
}
