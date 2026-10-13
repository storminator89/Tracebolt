package enrollmentstate

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestMacOSStoreImmutablePlatformFence(t *testing.T) {
	c := DefaultConfig(binding())
	before, _ := json.Marshal(c)
	if bytes.Contains(before, []byte("Platform")) {
		t.Fatal("historical config bytes changed")
	}
	c.Platform = "darwin"
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux", "windows", "macos", ""} {
		cmd := createCommand(1)
		cmd.Platform = platform
		if _, err = e.CreateInvitation(context.Background(), cmd); err == nil {
			t.Fatal("foreign platform admitted", platform)
		}
	}
	cmd := createCommand(1)
	cmd.Platform = "darwin"
	if _, err = e.CreateInvitation(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreTrustedLedger(c, raw); err != nil {
		t.Fatal(err)
	}
	old := c
	old.Platform = ""
	if _, err = RestoreTrustedLedger(old, raw); err == nil {
		t.Fatal("platform removed on reopen")
	}
	// Equal-length snapshot corruption keeps all ledger frame lengths intact.
	corrupt := bytes.Replace(raw, []byte(`"platform":"darwin"`), []byte(`"platform":"linuxx"`), 1)
	if _, err = RestoreTrustedLedger(c, corrupt); err == nil {
		t.Fatal("mixed snapshot admitted")
	}
	// A structurally valid Linux snapshot is also denied even if injected before encoding.
	rec := e.records[cmd.InvitationID]
	rec.snapshot.Platform = "linux"
	e.records[cmd.InvitationID] = rec
	corrupt, err = e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreTrustedLedger(c, corrupt); err == nil {
		t.Fatal("valid foreign snapshot admitted")
	}
	for _, collection := range []string{enrollmentcrypto.CollectionProfileComplete, enrollmentcrypto.CollectionProfileWindowsInventory} {
		invalid := c
		invalid.Binding.CollectionProfile = collection
		if _, err = New(invalid); err == nil {
			t.Fatal("scope promoted")
		}
	}
	invalid := c
	invalid.Binding.Profile = "http-test"
	invalid.Binding.Origin = "http://manager.example"
	if _, err = New(invalid); err == nil {
		t.Fatal("HTTP Mac domain admitted")
	}
}
