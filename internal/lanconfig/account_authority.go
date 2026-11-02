package lanconfig

import (
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"os"
	"path/filepath"
)

const AccountAuthorityVersion = "tracebolt.operator-auth.v3"
const AccountAuthorityMarkerVersion = "tracebolt.operator-authority-used.v1"
const AccountAuthorityMarkerFile = "operator-authority-used.json"
const AccountAuthorityJournalFile = "operator-accounts.jsonl"

// AccountAuthorityReference is an explicit protected reference, never live
// authority by itself. Startup opens the exact journal after writer admission.
type AccountAuthorityReference struct {
	SchemaVersion string `json:"schemaVersion"`
	Profile       string `json:"profile"`
	AuthorityID   string `json:"authorityId"`
	AuthorityFile string `json:"authorityFile"`
}

func (AccountAuthorityReference) String() string {
	return "lanconfig.AccountAuthorityReference{redacted}"
}
func (AccountAuthorityReference) GoString() string {
	return "lanconfig.AccountAuthorityReference{redacted}"
}

func ParseAccountAuthority(raw []byte, profile string) (*AccountAuthorityReference, error) {
	var ref AccountAuthorityReference
	if len(raw) > 4096 || StrictObject(raw, &ref, "schemaVersion", "profile", "authorityId", "authorityFile") != nil ||
		ref.SchemaVersion != AccountAuthorityVersion || profile != TLS || ref.Profile != profile ||
		!enrollmentcrypto.ValidID(ref.AuthorityID, "authority_") || !filepath.IsAbs(ref.AuthorityFile) || filepath.Clean(ref.AuthorityFile) != ref.AuthorityFile {
		return nil, ErrConfiguration
	}
	return &ref, nil
}

func loadOperatorMaterial(raw []byte, profile string) (string, []operatorauth.Operator, *AccountAuthorityReference, error) {
	fields, err := authMembers(raw, "schemaVersion", "profile", "passwordHash", "operators", "authorityId", "authorityFile")
	if err != nil {
		return "", nil, nil, ErrConfiguration
	}
	var version string
	if json.Unmarshal(fields["schemaVersion"], &version) != nil {
		return "", nil, nil, ErrConfiguration
	}
	if version == AccountAuthorityVersion {
		ref, err := ParseAccountAuthority(raw, profile)
		return "", nil, ref, err
	}
	hash, ops, err := loadOperatorAuth(raw, profile)
	return hash, ops, nil, err
}

// LoadNamedOperatorSeed accepts only an existing protected named-v2 snapshot.
// It never manufactures manage_accounts, credentials, identities or runtime state.
func LoadNamedOperatorSeed(path, profile string) ([]operatorauth.Operator, error) {
	if profile != TLS {
		return nil, ErrConfiguration
	}
	raw, err := ReadProtected(path, true, 32768)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer clear(raw)
	hash, ops, err := loadOperatorAuth(raw, profile)
	if err != nil || hash != "" || len(ops) == 0 {
		return nil, ErrConfiguration
	}
	admin := false
	for _, op := range ops {
		for _, c := range op.Capabilities {
			if c == operatorauth.ManageAccounts {
				admin = true
			}
		}
	}
	if !admin {
		return nil, ErrConfiguration
	}
	return ops, nil
}

type accountAuthorityMarker struct {
	Version       string `json:"version"`
	Profile       string `json:"profile"`
	AuthorityID   string `json:"authorityId"`
	AuthorityFile string `json:"authorityFile"`
}

// AccountAuthorityMarkerBytes is used only by create-only provisioning. The
// fixed in-state journal and immutable marker prevent ordinary missing-ledger
// reseeding and v3-to-v2 fallback; they do not defeat privileged full rollback.
func AccountAuthorityMarkerBytes(state string, ref AccountAuthorityReference) ([]byte, error) {
	if !filepath.IsAbs(state) || filepath.Clean(state) != state || ref.SchemaVersion != AccountAuthorityVersion || ref.Profile != TLS || !enrollmentcrypto.ValidID(ref.AuthorityID, "authority_") || ref.AuthorityFile != filepath.Join(state, AccountAuthorityJournalFile) {
		return nil, ErrConfiguration
	}
	return json.Marshal(accountAuthorityMarker{AccountAuthorityMarkerVersion, ref.Profile, ref.AuthorityID, ref.AuthorityFile})
}
func validateAccountAuthorityMarker(raw []byte, state string, ref *AccountAuthorityReference) error {
	if ref == nil {
		return ErrConfiguration
	}
	var marker accountAuthorityMarker
	if StrictObject(raw, &marker, "version", "profile", "authorityId", "authorityFile") != nil || marker.Version != AccountAuthorityMarkerVersion {
		return ErrConfiguration
	}
	expected, err := AccountAuthorityMarkerBytes(state, *ref)
	if err != nil {
		return err
	}
	var canonical accountAuthorityMarker
	if json.Unmarshal(expected, &canonical) != nil || marker != canonical {
		return ErrConfiguration
	}
	return nil
}

// CheckAccountAuthorityMarker is read-only and must precede authority use, under
// the manager's exclusive writer lease. A used marker denies static fallback even
// if the journal is missing. A v3 reference without its marker is never adopted.
func CheckAccountAuthorityMarker(state string, ref *AccountAuthorityReference) error {
	if !filepath.IsAbs(state) || filepath.Clean(state) != state {
		return ErrConfiguration
	}
	path := filepath.Join(state, AccountAuthorityMarkerFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if ref == nil {
			return nil
		}
		return ErrConfiguration
	} else if err != nil {
		return ErrConfiguration
	}
	raw, err := ReadProtected(path, true, 4096)
	if err != nil {
		return ErrConfiguration
	}
	return validateAccountAuthorityMarker(raw, state, ref)
}
