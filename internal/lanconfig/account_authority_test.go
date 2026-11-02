package lanconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

const liveReference = `{"schemaVersion":"tracebolt.operator-auth.v3","profile":"tls","authorityId":"authority_11111111111111111111111111111111","authorityFile":"/private/state/operator-accounts.jsonl"}`

func TestAccountAuthorityReferenceStrictAndTLSOnly(t *testing.T) {
	ref, err := ParseAccountAuthority([]byte(liveReference), TLS)
	if err != nil || ref.AuthorityFile != "/private/state/operator-accounts.jsonl" {
		t.Fatal("valid live reference rejected")
	}
	hash, ops, loaded, err := loadOperatorMaterial([]byte(liveReference), TLS)
	if err != nil || hash != "" || ops != nil || loaded == nil || *loaded != *ref {
		t.Fatal("v3 reference mixed with startup credentials")
	}
	if ValidateOperatorAuth([]byte(liveReference), TLS) != nil {
		t.Fatal("schema-only validation rejected reference")
	}
	for _, bad := range []string{
		liveReference + `{}`,
		strings.Replace(liveReference, `"profile":"tls"`, `"profile":"tls","profile":"tls"`, 1),
		strings.Replace(liveReference, `"authorityId"`, `"AuthorityId"`, 1),
		strings.Replace(liveReference, `"authorityId":"authority_11111111111111111111111111111111"`, `"authorityId":null`, 1),
		strings.Replace(liveReference, `authority_11111111111111111111111111111111`, `authority_00000000000000000000000000000000`, 1),
		strings.Replace(liveReference, `/private/state/operator-accounts.jsonl`, `relative.jsonl`, 1),
		strings.Replace(liveReference, `/private/state/operator-accounts.jsonl`, `/private/state/../operator-accounts.jsonl`, 1),
		strings.Replace(liveReference, `"profile":"tls"`, `"profile":"http-test"`, 1),
		strings.Replace(liveReference, `"profile":"tls"`, `"profile":"tls","operators":[]`, 1),
		strings.Replace(liveReference, `"profile":"tls"`, `"profile":"tls","passwordHash":"fixture-secret"`, 1),
		strings.Replace(liveReference, `"authorityFile":"/private/state/operator-accounts.jsonl"`, `"authorityFile":{"path":"/private/other"}`, 1),
	} {
		if _, _, _, err := loadOperatorMaterial([]byte(bad), TLS); err == nil {
			t.Fatal("ambiguous live authority reference accepted")
		}
	}
	if _, err := ParseAccountAuthority([]byte(liveReference), HTTPTest); err == nil {
		t.Fatal("live authority promoted into plaintext profile")
	}
	if _, _, err := loadOperatorAuth([]byte(liveReference), TLS); err == nil {
		t.Fatal("legacy parser adopted live reference")
	}
}
func TestAccountAuthorityMarkerPinsUsedModeAndExactPath(t *testing.T) {
	ref, err := ParseAccountAuthority([]byte(liveReference), TLS)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := AccountAuthorityMarkerBytes("/private/state", *ref)
	if err != nil {
		t.Fatal(err)
	}
	if validateAccountAuthorityMarker(raw, "/private/state", ref) != nil {
		t.Fatal("exact marker rejected")
	}
	if validateAccountAuthorityMarker(raw, "/private/state", nil) == nil {
		t.Fatal("used authority allowed static downgrade")
	}
	wrong := *ref
	wrong.AuthorityID = "authority_22222222222222222222222222222222"
	if validateAccountAuthorityMarker(raw, "/private/state", &wrong) == nil {
		t.Fatal("other authority adopted")
	}
	wrong = *ref
	wrong.AuthorityFile = "/private/other/operator-accounts.jsonl"
	if validateAccountAuthorityMarker(raw, "/private/state", &wrong) == nil {
		t.Fatal("other ledger adopted")
	}
	if validateAccountAuthorityMarker(raw, "/private/other", ref) == nil {
		t.Fatal("other state adopted")
	}
	for _, bad := range [][]byte{nil, []byte(`{}`), append(append([]byte(nil), raw...), []byte(`{}`)...), []byte(strings.Replace(string(raw), `"profile":"tls"`, `"profile":"tls","profile":"tls"`, 1))} {
		if validateAccountAuthorityMarker(bad, "/private/state", ref) == nil {
			t.Fatal("corrupt marker adopted")
		}
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil || len(object) != 4 {
		t.Fatal("unexpected marker payload")
	}
}
func TestAccountAuthorityMarkerNeverSeedsMissingState(t *testing.T) {
	state := t.TempDir()
	if CheckAccountAuthorityMarker(state, nil) != nil {
		t.Fatal("untouched static mode rejected")
	}
	ref := &AccountAuthorityReference{SchemaVersion: AccountAuthorityVersion, Profile: TLS, AuthorityID: "authority_11111111111111111111111111111111", AuthorityFile: state + "/operator-accounts.jsonl"}
	if CheckAccountAuthorityMarker(state, ref) == nil {
		t.Fatal("missing used marker adopted")
	}
}

func TestManageAccountsSeedGrantIsExplicitAndNonAliasing(t *testing.T) {
	raw := strings.Replace(namedAuthJSON(), `"read","restart_service"`, `"read","manage_accounts"`, 1)
	if _, ops, err := loadOperatorAuth([]byte(raw), HTTPTest); err != nil || len(ops) != 1 || len(ops[0].Capabilities) != 2 {
		t.Fatal("explicit new capability rejected")
	}
	for _, bad := range []string{
		strings.Replace(raw, `"read","manage_accounts"`, `"manage_accounts"`, 1),
		strings.Replace(raw, `"manage_accounts"`, `"manage_accounts","manage_accounts"`, 1),
		strings.Replace(raw, `"manage_accounts"`, `"Manage_accounts"`, 1),
	} {
		if _, _, err := loadOperatorAuth([]byte(bad), HTTPTest); err == nil {
			t.Fatal("ambiguous account-management authority accepted")
		}
	}
}
