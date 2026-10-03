package enrollmentstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStrictSnapshotJSONAndAllPhases(t *testing.T) {
	for _, build := range []func(*testing.T, *Engine, int) Snapshot{create, pending, approved, intended, issued, activated} {
		e := engine(t)
		s := build(t, e, 1)
		raw, err := EncodeSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		out, err := DecodeSnapshot(raw)
		if err != nil || out != s {
			t.Fatalf("roundtrip %s: %v", s.State, err)
		}
	}
	e := engine(t)
	s := pending(t, e, 1)
	raw, _ := EncodeSnapshot(s)
	bad := map[string][]byte{
		"empty": nil, "oversize": bytes.Repeat([]byte(" "), MaxJSONBytes+1), "trailing": append(bytes.Clone(raw), []byte(" {}")...),
		"unknown":             bytes.Replace(raw, []byte(`"version":`), []byte(`"extra":1,"version":`), 1),
		"duplicate":           bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"bad","version":`), 1),
		"escaped duplicate":   bytes.Replace(raw, []byte(`"version":`), []byte(`"\u0076ersion":"bad","version":`), 1),
		"case alias":          bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1),
		"missing":             bytes.Replace(raw, []byte(`"version":"`+SnapshotVersion+`",`), nil, 1),
		"null nested":         bytes.Replace(raw, []byte(`"claim":{`), []byte(`"claim":null,"ignored":{`), 1),
		"wrong type":          bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":"2"`), 1),
		"negative revision":   bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":-1`), 1),
		"fraction revision":   bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":2.0`), 1),
		"exponent revision":   bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":2e0`), 1),
		"overflow revision":   bytes.Replace(raw, []byte(`"revision":2`), []byte(`"revision":18446744073709551616`), 1),
		"duplicate nested":    bytes.Replace(raw, []byte(`"claimID":`), []byte(`"claimID":"bad","claimID":`), 1),
		"unicode replacement": bytes.Replace(raw, []byte(`"linux"`), []byte(`"\ud800"`), 1),
		"invalid utf8":        append(bytes.Clone(raw), 0xff),
		"array":               []byte(`[]`), "deep": []byte(strings.Repeat(`{"x":`, 20) + `1` + strings.Repeat(`}`, 20)),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSnapshot(b); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted invalid JSON: %v", err)
			}
		})
	}
}

func TestInvalidSnapshotStateShape(t *testing.T) {
	e := engine(t)
	s := activated(t, e, 1)
	for name, change := range map[string]func(*Snapshot){
		"version": func(s *Snapshot) { s.Version = "v1" }, "unknown state": func(s *Snapshot) { s.State = "renewed" }, "missing claim": func(s *Snapshot) { s.Claim = ClaimBinding{} }, "missing approval": func(s *Snapshot) { s.Approval = Approval{} }, "key substitution": func(s *Snapshot) { s.Approval.KeyFingerprint = hash(999) }, "identity substitution": func(s *Snapshot) { s.Intent.DeviceID = id("agent", 9) }, "unbounded validity": func(s *Snapshot) { s.Intent.NotAfter = s.Intent.NotBefore + MaxCertificateTTL + 1 }, "expired activation": func(s *Snapshot) { s.Activation.At = s.DeadlineAt; s.UpdatedAt = s.DeadlineAt }, "bad code": func(s *Snapshot) { s.Claim.ComparisonCode = "123456" }, "uppercase hash": func(s *Snapshot) { s.Claim.CSRHash = strings.Repeat("A", 64) }, "zero hash": func(s *Snapshot) { s.Issuance.CertificateHash = hash(0) }, "terminal metadata": func(s *Snapshot) { s.Termination.RequestID = id("request", 900) }, "time regression": func(s *Snapshot) { s.Intent.At = s.Approval.At - 1 }, "revision exhausted": func(s *Snapshot) { s.Revision = MaxRevision + 1 }, "state shape": func(s *Snapshot) { s.State = Created },
	} {
		t.Run(name, func(t *testing.T) {
			copy := s
			change(&copy)
			if ValidateSnapshot(copy) == nil {
				t.Fatal("accepted invalid snapshot")
			}
			raw, _ := json.Marshal(copy)
			if _, err := DecodeSnapshot(raw); err == nil {
				t.Fatal("decoded invalid snapshot")
			}
			if _, err := EncodeSnapshot(copy); err == nil {
				t.Fatal("encoded invalid snapshot")
			}
		})
	}
}

func TestStrictCommandsAndBounds(t *testing.T) {
	e := engine(t)
	s := approved(t, e, 1)
	commands := []struct {
		value  any
		decode func([]byte) error
	}{
		{createCommand(2), func(b []byte) error { _, e := DecodeCreateCommand(b); return e }},
		{ClaimCommand{Control: control(s, 200), ClaimID: id("claim", 2)}, func(b []byte) error { _, e := DecodeClaimCommand(b); return e }},
		{ApproveCommand{Control: control(s, 200), DeviceID: id("agent", 2), KeyFingerprint: hash(1)}, func(b []byte) error { _, e := DecodeApproveCommand(b); return e }},
		{intentCommand(s, 1), func(b []byte) error { _, e := DecodeIntentCommand(b); return e }},
		{control(s, 200), func(b []byte) error { _, e := DecodeControl(b); return e }},
		{TerminalCommand{Control: control(s, 200), State: Revoked}, func(b []byte) error { _, e := DecodeTerminalCommand(b); return e }},
	}
	for _, c := range commands {
		raw, _ := json.Marshal(c.value)
		if err := c.decode(raw); err != nil {
			t.Fatalf("valid %T: %v", c.value, err)
		}
		for _, b := range [][]byte{append(bytes.Clone(raw), []byte("null")...), append([]byte(`{"unknown":true,`), raw[1:]...), []byte(`{}`), []byte(`null`)} {
			if c.decode(b) == nil {
				t.Fatalf("invalid %T", c.value)
			}
		}
	}
	for name, change := range map[string]func(*CreateCommand){"zero id": func(c *CreateCommand) { c.InvitationID = id("invite", 0) }, "long id": func(c *CreateCommand) { c.InvitationID += "0" }, "alias id": func(c *CreateCommand) { c.InvitationID = "INVITE_" + strings.Repeat("a", 32) }, "wrong prefix": func(c *CreateCommand) { c.InvitationID = id("claim", 1) }, "short hash": func(c *CreateCommand) { c.InvitationHash = "abc" }, "zero hash": func(c *CreateCommand) { c.InvitationHash = hash(0) }, "unknown platform": func(c *CreateCommand) { c.Platform = "any" }, "zero time": func(c *CreateCommand) { c.Now = 0 }, "overflow time": func(c *CreateCommand) { c.Now = MaxTimestamp }} {
		t.Run(name, func(t *testing.T) {
			c := createCommand(2)
			change(&c)
			raw, _ := json.Marshal(c)
			if _, err := DecodeCreateCommand(raw); err == nil {
				t.Fatal("accepted invalid command")
			}
		})
	}
	c := createCommand(2)
	c.Now = MaxTimestamp - MaxPendingTTL - MaxInvitationTTL
	raw, _ := json.Marshal(c)
	if _, err := DecodeCreateCommand(raw); err != nil {
		t.Fatal(err)
	}
	ctrl := control(s, 200)
	ctrl.ExpectedRevision = MaxRevision
	raw, _ = json.Marshal(ctrl)
	if _, err := DecodeControl(raw); err != nil {
		t.Fatal(err)
	}
	ctrl.ExpectedRevision++
	raw, _ = json.Marshal(ctrl)
	if _, err := DecodeControl(raw); err == nil {
		t.Fatal("accepted exhausted revision")
	}
}

func FuzzDecodeSnapshot(f *testing.F) {
	e, err := New(DefaultConfig(binding()))
	if err != nil {
		f.Fatal(err)
	}
	s, err := e.CreateInvitation(context.Background(), createCommand(1))
	if err != nil {
		f.Fatal(err)
	}
	valid, err := EncodeSnapshot(s)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":"tracebolt.enrollment-state.v2"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := DecodeSnapshot(raw)
		if err != nil {
			return
		}
		if ValidateSnapshot(s) != nil {
			t.Fatal("decoder returned invalid snapshot")
		}
		encoded, err := EncodeSnapshot(s)
		if err != nil {
			t.Fatal(err)
		}
		out, err := DecodeSnapshot(encoded)
		if err != nil || out != s {
			t.Fatal("unstable roundtrip")
		}
	})
}

func FuzzDecodeCreateCommand(f *testing.F) {
	b, _ := json.Marshal(createCommand(1))
	f.Add(b)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := DecodeCreateCommand(raw)
		if err != nil {
			return
		}
		if validateCreate(c) != nil {
			t.Fatal("decoder returned invalid command")
		}
		encoded, _ := json.Marshal(c)
		out, err := DecodeCreateCommand(encoded)
		if err != nil || out != c {
			t.Fatal("unstable command")
		}
	})
}
