package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
)

var errSetup = errors.New("HTTP-test setup failed")
var fileNames = [...]string{"http-test.json", "operator-auth.json", "enrollment.json", "client-issuer.pem", "client-issuer.key", "client-root.pem"}

type materialFile struct {
	name string
	data []byte
}

func clearFiles(files []materialFile) {
	for _, f := range files {
		clear(f.data)
	}
}
func validIP(raw string) bool {
	a, e := netip.ParseAddr(raw)
	return e == nil && a.Is4() && a.IsPrivate() && a.String() == raw
}
func validPassword(p []byte) bool {
	if len(p) < 12 || len(p) > 1024 || !utf8.Valid(p) {
		return false
	}
	for len(p) > 0 {
		r, n := utf8.DecodeRune(p)
		if unicode.IsControl(r) {
			return false
		}
		p = p[n:]
	}
	return true
}
func generate(profile setupProfile, ip string, password []byte, random io.Reader, now time.Time) (files []materialFile, err error) {
	if _, _, _, e := profile.paths(); e != nil {
		return nil, errSetup
	}
	if !validIP(ip) || !validPassword(password) || random == nil || now.Unix() <= 0 {
		return nil, errSetup
	}
	defer func() {
		if err != nil {
			clearFiles(files)
		}
	}()
	salt := make([]byte, 16)
	if _, err = io.ReadFull(random, salt); err != nil {
		return nil, errSetup
	}
	defer clear(salt)
	hash := argon2.IDKey(password, salt, 2, 65536, 1, 32)
	defer clear(hash)
	phc := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	if _, err = operatorauth.New(operatorauth.Config{PasswordHash: phc}); err != nil {
		return nil, errSetup
	}
	rootPublic, rootKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, errSetup
	}
	defer clear(rootKey)
	issuerPublic, issuerKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, errSetup
	}
	defer clear(issuerKey)
	serial := func() (*big.Int, error) {
		b := make([]byte, 16)
		if _, e := io.ReadFull(random, b); e != nil {
			return nil, e
		}
		b[0] |= 1
		return new(big.Int).SetBytes(b), nil
	}
	rootSerial, err := serial()
	if err != nil {
		return nil, errSetup
	}
	issuerSerial, err := serial()
	if err != nil {
		return nil, errSetup
	}
	rootID, issuerID := sha256.Sum256(rootPublic), sha256.Sum256(issuerPublic)
	root := &x509.Certificate{SerialNumber: rootSerial, Subject: pkix.Name{CommonName: "Tracebolt disposable HTTP-test root"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(31 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: rootID[:20], SignatureAlgorithm: x509.PureEd25519}
	rootDER, err := x509.CreateCertificate(random, root, root, rootPublic, rootKey)
	if err != nil {
		return nil, errSetup
	}
	issuer := &x509.Certificate{SerialNumber: issuerSerial, Subject: pkix.Name{CommonName: "Tracebolt disposable HTTP-test client issuer"}, NotBefore: root.NotBefore, NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: issuerID[:20], AuthorityKeyId: rootID[:20], SignatureAlgorithm: x509.PureEd25519}
	issuerDER, err := x509.CreateCertificate(random, issuer, root, issuerPublic, rootKey)
	if err != nil {
		return nil, errSetup
	}
	clear(rootKey) // Never encoded, persisted or available for future root operations.
	fingerprint := sha256.Sum256(issuerDER)
	fingerprintText := hex.EncodeToString(fingerprint[:])
	if enrollmentissuer.ValidatePublicAuthority(issuerDER, rootDER, fingerprintText, now) != nil {
		return nil, errSetup
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		return nil, errSetup
	}
	defer clear(keyDER)
	instance := make([]byte, 16)
	if _, err = io.ReadFull(random, instance); err != nil {
		return nil, errSetup
	}
	lan := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: lanconfig.HTTPTest, OperatorListen: "0.0.0.0:8787", AgentListen: "0.0.0.0:8788", OperatorOrigin: "http://" + ip + ":8787", AgentOrigin: "http://" + ip + ":8788", AgentClientCAFile: "/run/tracebolt/client-issuer.pem", OperatorAuthFile: "/run/tracebolt/operator-auth.json", StateDirectory: "/data/state", WebDirectory: "/tracebolt/web", InsecureHTTPAcknowledged: true}
	if lan.Validate() != nil {
		return nil, errSetup
	}
	// Preserve omitted/basic compatibility; only the explicit fresh inventory
	// selections serialize their exact separately consented collectionProfile.
	enrollment := enrollmentconfig.Config{SchemaVersion: enrollmentconfig.SchemaVersion, Profile: lanconfig.HTTPTest, InstanceID: "manager_" + hex.EncodeToString(instance), IssuerCertificateFile: "/run/tracebolt/client-issuer.pem", IssuerPrivateKeyFile: "/run/tracebolt/client-issuer.key", IssuerRootFile: "/run/tracebolt/client-root.pem", ExpectedIssuerFingerprint: fingerprintText, BootstrapServerCAFile: ""}
	if profile == inventorySetup {
		enrollment.CollectionProfile = inventoryProfileName
	}
	if profile == completeSetup {
		enrollment.CollectionProfile = completeProfileName
	}
	auth := struct {
		SchemaVersion string `json:"schemaVersion"`
		Profile       string `json:"profile"`
		PasswordHash  string `json:"passwordHash"`
	}{"tracebolt.operator-auth.v1", lanconfig.HTTPTest, phc}
	for i, v := range []any{lan, auth, enrollment} {
		raw, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return files, errSetup
		}
		files = append(files, materialFile{fileNames[i], append(raw, '\n')})
	}
	files = append(files, materialFile{fileNames[3], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})}, materialFile{fileNames[4], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}, materialFile{fileNames[5], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})})
	return files, nil
}
