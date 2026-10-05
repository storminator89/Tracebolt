package lanconfig

import (
	"bytes"
	"encoding/json"
	"io"
	"localrmm/internal/operatorauth"
	"unicode/utf8"
)

// authMembers rejects ambiguous keys before typed JSON decoding. It allows
// nesting only for the v2 operators/capabilities shapes, decoded separately.
func authMembers(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return nil, ErrConfiguration
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, ErrConfiguration
	}
	members := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		t, err := d.Token()
		key, ok := t.(string)
		if err != nil || !ok || !allowed[key] || members[key] != nil {
			return nil, ErrConfiguration
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrConfiguration
		}
		members[key] = value
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return nil, ErrConfiguration
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrConfiguration
	}
	return members, nil
}

func loadOperatorAuth(raw []byte, profile string) (string, []operatorauth.Operator, error) {
	bad := func() (string, []operatorauth.Operator, error) { return "", nil, ErrConfiguration }
	members, err := authMembers(raw, "schemaVersion", "profile", "passwordHash", "operators")
	if err != nil {
		return bad()
	}
	var version, boundProfile string
	if json.Unmarshal(members["schemaVersion"], &version) != nil || json.Unmarshal(members["profile"], &boundProfile) != nil || boundProfile != profile {
		return bad()
	}
	switch version {
	case "tracebolt.operator-auth.v1":
		if len(raw) > 4096 {
			return bad()
		}
		var a struct {
			SchemaVersion string `json:"schemaVersion"`
			Profile       string `json:"profile"`
			PasswordHash  string `json:"passwordHash"`
		}
		if StrictObject(raw, &a, "schemaVersion", "profile", "passwordHash") != nil || a.PasswordHash == "" {
			return bad()
		}
		return a.PasswordHash, nil, nil
	case "tracebolt.operator-auth.v2":
		if len(members) != 3 || members["operators"] == nil || members["passwordHash"] != nil {
			return bad()
		}
		var records []json.RawMessage
		if json.Unmarshal(members["operators"], &records) != nil || len(records) < 1 || len(records) > operatorauth.MaxOperators {
			return bad()
		}
		operators := make([]operatorauth.Operator, 0, len(records))
		for _, record := range records {
			fields, err := authMembers(record, "id", "username", "passwordHash", "capabilities")
			if err != nil || len(fields) != 4 {
				return bad()
			}
			var op operatorauth.Operator
			if json.Unmarshal(fields["id"], &op.ID) != nil || json.Unmarshal(fields["username"], &op.Username) != nil || json.Unmarshal(fields["passwordHash"], &op.PasswordHash) != nil || json.Unmarshal(fields["capabilities"], &op.Capabilities) != nil {
				return bad()
			}
			operators = append(operators, op)
		}
		// Validate the whole immutable authority snapshot before opening stores
		// or listeners. No credentials or accounts are created here.
		if _, err := operatorauth.New(operatorauth.Config{Operators: operators}); err != nil {
			return bad()
		}
		return "", operators, nil
	default:
		return bad()
	}
}
