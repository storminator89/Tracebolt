//go:build linux

package operatorauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCredentialProposalParserExactBinding(t *testing.T) {
	const authority = "authority_11111111111111111111111111111111"
	const actor = "operator_00000000000000000000000000000002"
	hash := fixtureHash()
	encodedHash, _ := json.Marshal(hash)
	raw := []byte(`{"version":"tracebolt.operator-credential-proposal.v1","authorityId":"` + authority + `","actorId":"` + actor + `","expectedRevision":7,"passwordHash":` + string(encodedHash) + `}`)
	for _, data := range [][]byte{raw, append(append([]byte(" \n"), raw...), '\n')} {
		before := append([]byte(nil), data...)
		got, err := parseCredentialProposal(data, authority, actor, 7)
		if err != nil || got != hash {
			t.Fatalf("valid exact-bound proposal rejected: %v", err)
		}
		if !bytes.Equal(data, before) {
			t.Fatal("parser modified caller bytes")
		}
	}
	tests := map[string][]byte{
		"duplicate":       bytes.Replace(raw, []byte(`"expectedRevision":7`), []byte(`"expectedRevision":7,"expectedRevision":7`), 1),
		"unknown":         bytes.Replace(raw, []byte(`"expectedRevision":7`), []byte(`"extra":false,"expectedRevision":7`), 1),
		"reordered":       bytes.Replace(raw, []byte(`"actorId":"`+actor+`","expectedRevision":7`), []byte(`"expectedRevision":7,"actorId":"`+actor+`"`), 1),
		"authority":       bytes.Replace(raw, []byte(authority), []byte("authority_22222222222222222222222222222222"), 1),
		"actor":           bytes.Replace(raw, []byte(actor), []byte("operator_00000000000000000000000000000003"), 1),
		"revision":        bytes.Replace(raw, []byte(`"expectedRevision":7`), []byte(`"expectedRevision":8`), 1),
		"version":         bytes.Replace(raw, []byte("proposal.v1"), []byte("proposal.v2"), 1),
		"empty_hash":      bytes.Replace(raw, encodedHash, []byte(`""`), 1),
		"bad_hash":        bytes.Replace(raw, encodedHash, []byte(`"bad"`), 1),
		"missing_hash":    bytes.Replace(raw, append([]byte(`,"passwordHash":`), encodedHash...), nil, 1),
		"null":            []byte("null"),
		"empty":           nil,
		"trailing_object": append(append([]byte(nil), raw...), []byte("{}")...),
		"oversize":        append(append([]byte(nil), raw...), []byte(strings.Repeat(" ", 4097-len(raw)))...),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseCredentialProposal(data, authority, actor, 7)
			if !errors.Is(err, ErrConfiguration) || got != "" {
				t.Fatalf("invalid proposal accepted: err=%v, returned verifier=%t", err, got != "")
			}
		})
	}
	for name, binding := range map[string]struct {
		authority, actor string
		revision         uint64
	}{
		"authority": {authority + "0", actor, 7}, "actor": {authority, actor + "0", 7}, "revision": {authority, actor, 8},
	} {
		t.Run("expected_"+name, func(t *testing.T) {
			if got, err := parseCredentialProposal(raw, binding.authority, binding.actor, binding.revision); err != ErrConfiguration || got != "" {
				t.Fatal("mismatched expected binding accepted")
			}
		})
	}
}
