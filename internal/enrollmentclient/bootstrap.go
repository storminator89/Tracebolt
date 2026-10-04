// Package enrollmentclient implements the Linux guided enrollment handoff to the
// existing foreground LAN sender. It installs no service and changes no OS trust.
package enrollmentclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanconfig"
	"reflect"
	"time"
	"unicode/utf8"
)

var (
	ErrBootstrap  = errors.New("enrollment bootstrap or explicit trust is invalid")
	ErrState      = errors.New("private enrollment state is unavailable or incompatible; no reset was performed")
	ErrLocked     = errors.New("enrollment state is already in use")
	ErrResponse   = errors.New("enrollment response violates the locally bound contract")
	ErrTransport  = errors.New("enrollment was not acknowledged; private state retained for reconciliation")
	ErrInvitation = errors.New("invitation was rejected or differs from the saved semantic claim; private state retained")
	ErrTerminal   = errors.New("enrollment is expired, canceled, rejected or revoked")
	ErrInput      = errors.New("enrollment invitation input is unavailable or invalid")
)

const BootstrapVersion = "tracebolt.enrollment-bootstrap.v2"
const maxJSON = 64 << 10

type Bootstrap struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	EnrollmentOrigin  string `json:"enrollmentOrigin"`
	AgentOrigin       string `json:"agentOrigin"`
	CollectionProfile string `json:"collectionProfile"`
	InvitationID      string `json:"invitationId"`
	ServerCAPEM       string `json:"serverCaPem"`
	IssuerRootPEM     string `json:"issuerRootPem"`
	IssuerPEM         string `json:"issuerPem"`
}

// TrustDisplay is locally validated public context. Display must complete before
// Secret is invoked or any request is sent. HTTPTest remains a permanent warning.
type TrustDisplay struct {
	ManagerInstanceID, Profile, EnrollmentOrigin, AgentOrigin, CollectionProfile, InvitationID string
	ServerCAFingerprints                                                                       []string
	IssuerRootFingerprint, IssuerFingerprint, KeyFingerprint, ComparisonCode                   string
	CollectionPrivacy                                                                          string
	HTTPTest                                                                                   bool
}

func LoadBootstrap(path string) (Bootstrap, error) {
	raw, err := lanconfig.ReadProtected(path, false, maxJSON)
	if err != nil {
		return Bootstrap{}, ErrBootstrap
	}
	return ParseBootstrap(raw)
}

// ParseBootstrap validates an already bounded public-only byte snapshot. It makes
// no filesystem or network changes; caller is responsible for its integrity.
func ParseBootstrap(raw []byte) (Bootstrap, error) {
	if len(raw) == 0 || len(raw) > maxJSON {
		return Bootstrap{}, ErrBootstrap
	}
	var b Bootstrap
	if strictJSON(raw, &b) != nil {
		return Bootstrap{}, ErrBootstrap
	}
	if _, err := validateBootstrap(b, time.Now()); err != nil {
		return Bootstrap{}, err
	}
	return b, nil
}

func fingerprint(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func publicCertificates(raw string) ([]*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > 32<<10 {
		return nil, ErrBootstrap
	}
	rest := []byte(raw)
	out := []*x509.Certificate{}
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrBootstrap
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, ErrBootstrap
		}
		end += len("-----END CERTIFICATE-----")
		segment := rest[:end]
		if bytes.Count(segment, []byte("-----BEGIN")) != 1 {
			return nil, ErrBootstrap
		}
		block, tail := pem.Decode(segment)
		next := rest[end:]
		if block == nil || len(bytes.TrimSpace(tail)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) > enrollmentcrypto.MaxCertificateBytes {
			return nil, ErrBootstrap
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrBootstrap
		}
		for _, prior := range out {
			if bytes.Equal(prior.Raw, cert.Raw) {
				return nil, ErrBootstrap
			}
		}
		out = append(out, cert)
		rest = next
		if len(out) > 8 {
			return nil, ErrBootstrap
		}
	}
	return out, nil
}
func validateBootstrap(b Bootstrap, now time.Time) (TrustDisplay, error) {
	fail := func() (TrustDisplay, error) { return TrustDisplay{}, ErrBootstrap }
	if b.SchemaVersion != BootstrapVersion || !enrollmentcrypto.ValidID(b.ManagerInstanceID, "manager_") || !enrollmentcrypto.ValidID(b.InvitationID, "invite_") || !enrollmentcrypto.ValidCollectionProfile(b.CollectionProfile) {
		return fail()
	}
	// Both destinations use the shared exact-origin and explicit-trust policy.
	for _, origin := range []string{b.EnrollmentOrigin, b.AgentOrigin} {
		c, err := lanclient.NewBootstrapHTTPClient(origin, b.Profile, []byte(b.ServerCAPEM))
		if err != nil {
			return fail()
		}
		c.CloseIdleConnections()
	}
	issuers, e := publicCertificates(b.IssuerPEM)
	if e != nil || len(issuers) != 1 {
		return fail()
	}
	roots, e := publicCertificates(b.IssuerRootPEM)
	if e != nil || len(roots) != 1 {
		return fail()
	}
	issuer, root := issuers[0], roots[0]
	if enrollmentissuer.ValidatePublicAuthority(issuer.Raw, root.Raw, fingerprint(issuer.Raw), now) != nil {
		return fail()
	}
	d := TrustDisplay{ManagerInstanceID: b.ManagerInstanceID, Profile: b.Profile, EnrollmentOrigin: b.EnrollmentOrigin, AgentOrigin: b.AgentOrigin, CollectionProfile: b.CollectionProfile, InvitationID: b.InvitationID, IssuerRootFingerprint: fingerprint(root.Raw), IssuerFingerprint: fingerprint(issuer.Raw), HTTPTest: b.Profile == "http-test"}
	if enrollmentcrypto.ManagedCollectionProfile(b.CollectionProfile) {
		d.CollectionPrivacy = "Includes volume mount labels and utilization, network interface names and counters, service unit names and states, process IDs and names and resource usage, installed package names and versions, and event unit/priority/count metadata. Names and mount paths can reveal personal or secret-like labels; this profile is not anonymous or guaranteed secret-free. No command lines, environment, account IDs, IP/MAC address values, raw log messages or package descriptions are collected. Operational metadata stays in the operator-only latest/last-good view and is not added to AI evidence."
	}
	if b.CollectionProfile == enrollmentcrypto.CollectionProfilePackages {
		d.CollectionPrivacy += " This fresh profile additionally reports exact selected OS release identifiers, binary/source package names and versions, source-mapping basis and installation state. Package rows are bounded and may be partial. No repository URLs, maintainer data, package descriptions, APT queries or update installation are included. The latest package frame remains stored until replaced, including after revocation; freshness expiry does not delete its bytes. Package metadata is excluded from AI export. Existing sender state cannot be adopted or reset into this profile."
	}
	if b.Profile == "tls" {
		cs, e := publicCertificates(b.ServerCAPEM)
		if e != nil {
			return fail()
		}
		for _, c := range cs {
			d.ServerCAFingerprints = append(d.ServerCAFingerprints, fingerprint(c.Raw))
		}
	}
	return d, nil
}

// strictJSON checks exact case, every field, duplicate keys, null, shape and
// bounds before decoding. No extension fields or coercion are accepted.
func strictJSON(raw []byte, out any) error {
	if wrapped, ok := out.(*ledger); ok {
		wrapped.ledgerData = &ledgerData{}
		out = wrapped.ledgerData
	}
	if len(raw) == 0 || len(raw) > maxJSON || !utf8.Valid(raw) {
		return ErrResponse
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if decodeShape(d, reflect.TypeOf(out).Elem(), 0) != nil {
		return ErrResponse
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrResponse
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrResponse
	}
	return nil
}
func decodeShape(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 8 {
		return ErrResponse
	}
	tok, e := d.Token()
	if e != nil || tok == nil {
		return ErrResponse
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return ErrResponse
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fields[f.Tag.Get("json")] = f.Type
		}
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			name, ok := k.(string)
			typ, known := fields[name]
			if e != nil || !ok || !known || seen[name] {
				return ErrResponse
			}
			seen[name] = true
			if decodeShape(d, typ, depth+1) != nil {
				return ErrResponse
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return ErrResponse
		}
	case reflect.String:
		s, ok := tok.(string)
		if !ok || !utf8.ValidString(s) || bytes.ContainsRune([]byte(s), '\ufffd') {
			return ErrResponse
		}
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return ErrResponse
		}
	case reflect.Uint64, reflect.Int64:
		if _, ok := tok.(json.Number); !ok {
			return ErrResponse
		}
	default:
		return ErrResponse
	}
	return nil
}
