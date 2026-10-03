package enrollmentissuer_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
)

var now = time.Unix(1791048000, 0).UTC()

// All material is ordinary generated, ephemeral test-only material. No test
// touches a live trust store, deployment, persistent credential or v1 endpoint.
type fixture struct {
	issuerDER, rootDER []byte
	key                ed25519.PrivateKey
	intent             enrollmentcrypto.Intent
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func makeFixture(t *testing.T, rootKey crypto.Signer, rootEdit, issuerEdit func(*x509.Certificate)) fixture {
	t.Helper()
	if rootKey == nil {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal("fixture root generation failed")
		}
		rootKey = key
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral offline test root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if rootEdit != nil {
		rootEdit(rootTemplate)
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal("fixture root certificate failed")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal("fixture root parse failed")
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture issuer generation failed")
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral client-only intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if issuerEdit != nil {
		issuerEdit(issuerTemplate)
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, public, rootKey)
	if err != nil {
		t.Fatal("fixture intermediate certificate failed")
	}
	endpointPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("fixture endpoint generation failed")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(endpointPublic)
	if err != nil {
		t.Fatal("fixture endpoint public encoding failed")
	}
	id := func(prefix string, value byte) string {
		return prefix + hex.EncodeToString(bytes.Repeat([]byte{value}, 16))
	}
	intent := enrollmentcrypto.Intent{
		ManagerInstanceID: id("manager_", 1), Profile: "tls", Origin: "https://manager.example.test:7443",
		CollectionProfile: enrollmentcrypto.CollectionProfile,
		InvitationID:      id("invite_", 2), ClaimID: id("claim_", 3), RequestID: id("request_", 4),
		DeviceID: id("agent_", 5), IntentID: id("intent_", 6), KeyFingerprint: hash(publicDER),
		PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(publicDER), CSRHash: hash([]byte("fixture CSR")),
		ClaimHash: hash([]byte("fixture claim")), IssuerFingerprint: hash(issuerDER),
		SerialHex: strings.Repeat("89", 16), TemplateVersion: enrollmentcrypto.TemplateVersion,
		KeyGeneration: 1, NotBefore: now.Add(-30 * time.Second).Unix(), NotAfter: now.Add(24 * time.Hour).Unix(),
	}
	return fixture{issuerDER: issuerDER, rootDER: rootDER, key: key, intent: intent}
}

func (f fixture) issuer(t *testing.T) *enrollmentissuer.Issuer {
	t.Helper()
	issuer, err := enrollmentissuer.New(f.issuerDER, f.rootDER, f.key, f.intent.IssuerFingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func TestFixedLeafAndExactReconstruction(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := makeFixture(t, nil, nil, nil)
			if profile == "http-test" {
				f.intent.Profile = profile
				f.intent.Origin = "http://127.0.0.1:8080"
			}
			i := f.issuer(t)
			result, err := i.Sign(context.Background(), f.intent, now)
			if err != nil || !result.Valid() || result.Intent() != f.intent {
				t.Fatal("fixed leaf signing failed", err)
			}
			der := result.DER()
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal("fixed leaf parse failed")
			}
			if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.MaxPathLen != -1 || leaf.MaxPathLenZero || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.SignatureAlgorithm != x509.PureEd25519 || leaf.PublicKeyAlgorithm != x509.Ed25519 {
				t.Fatal("fixed leaf role changed")
			}
			if leaf.Subject.CommonName != f.intent.DeviceID || len(leaf.Subject.Names) != 1 || len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses)+len(leaf.URIs) != 0 || leaf.NotBefore.Unix() != f.intent.NotBefore || leaf.NotAfter.Unix() != f.intent.NotAfter || fmt.Sprintf("%032x", leaf.SerialNumber) != f.intent.SerialHex || hash(leaf.RawSubjectPublicKeyInfo) != f.intent.KeyFingerprint {
				t.Fatal("fixed leaf immutable fields changed")
			}
			allowed := map[string]bool{"2.5.29.15": true, "2.5.29.19": true, "2.5.29.35": true, "2.5.29.37": true}
			for _, extension := range leaf.Extensions {
				if !allowed[extension.Id.String()] {
					t.Fatal("unexpected fixed leaf extension")
				}
			}
			if _, err := enrollmentcrypto.VerifyIssued(der, f.issuerDER, f.intent, now); err != nil {
				t.Fatal("independent intent verification failed")
			}
			root, _ := x509.ParseCertificate(f.rootDER)
			intermediate, _ := x509.ParseCertificate(f.issuerDER)
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(root)
			intermediates.AddCert(intermediate)
			options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			if _, err := leaf.Verify(options); err != nil {
				t.Fatal("explicit client chain verification failed", err)
			}
			options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if _, err := leaf.Verify(options); err == nil {
				t.Fatal("client leaf became server credential")
			}
			for _, handle := range []*enrollmentissuer.Issuer{i, f.issuer(t)} {
				for _, at := range []time.Time{now, now.Add(time.Hour)} {
					retry, err := handle.Sign(context.Background(), f.intent, at)
					if err != nil || !bytes.Equal(der, retry.DER()) {
						t.Fatal("exact retry changed after time or handle reconstruction", err)
					}
				}
			}
			if profile == "http-test" && base64.RawStdEncoding.EncodedLen(len(der)) > 4096 {
				t.Fatal("test-profile leaf exceeded header cap")
			}
		})
	}
}

func TestSupportedRootKeyCompatibility(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("ephemeral ECDSA fixture failed")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("ephemeral RSA fixture failed")
	}
	for name, key := range map[string]crypto.Signer{"ECDSA P256": ecdsaKey, "RSA 2048": rsaKey} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t, key, nil, nil)
			if _, err := f.issuer(t).Sign(context.Background(), f.intent, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConstructorRejectsIssuerRoleAndChain(t *testing.T) {
	for name, edit := range map[string]func(*x509.Certificate){
		"non CA":                      func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLenZero = false },
		"missing basic constraints":   func(c *x509.Certificate) { c.BasicConstraintsValid = false },
		"unconstrained intermediate":  func(c *x509.Certificate) { c.MaxPathLen = -1; c.MaxPathLenZero = false },
		"can issue CA":                func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false },
		"missing certificate signing": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign },
		"endpoint key usage":          func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageDigitalSignature },
		"missing EKU":                 func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"server EKU":                  func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"any EKU":                     func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} },
		"dual EKU":                    func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"unknown EKU":                 func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"unknown critical extension": func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
		"expired":     func(c *x509.Certificate) { c.NotAfter = now },
		"future":      func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) },
		"before root": func(c *x509.Certificate) { c.NotBefore = now.Add(-48 * time.Hour) },
		"after root":  func(c *x509.Certificate) { c.NotAfter = now.Add(91 * 24 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t, nil, nil, edit)
			if _, err := enrollmentissuer.New(f.issuerDER, f.rootDER, f.key, f.intent.IssuerFingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
				t.Fatal("invalid intermediate accepted", err)
			}
		})
	}
	f, other := makeFixture(t, nil, nil, nil), makeFixture(t, nil, nil, nil)
	for name, pair := range map[string][][]byte{
		"unrelated root":           {f.issuerDER, other.rootDER},
		"issuer as its own anchor": {f.issuerDER, f.issuerDER},
		"swapped chain":            {f.rootDER, f.issuerDER},
		"intermediate root":        {f.issuerDER, other.issuerDER},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := enrollmentissuer.New(pair[0], pair[1], f.key, hash(pair[0]), now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
				t.Fatal("unapproved chain accepted", err)
			}
		})
	}
}

func TestConstructorRejectsRootPolicy(t *testing.T) {
	for name, edit := range map[string]func(*x509.Certificate){
		"non CA":                      func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = 0 },
		"missing basic constraints":   func(c *x509.Certificate) { c.BasicConstraintsValid = false },
		"missing certificate signing": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign },
		"pathLen zero":                func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = true },
		"server only EKU":             func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"unknown EKU":                 func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		"expired":                     func(c *x509.Certificate) { c.NotAfter = now },
		"future":                      func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t, nil, edit, nil)
			if _, err := enrollmentissuer.New(f.issuerDER, f.rootDER, f.key, f.intent.IssuerFingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
				t.Fatal("invalid root accepted", err)
			}
		})
	}
}

func TestConstructorRejectsSharedOfflineRootKeyAndInvalidSignatures(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	rootTemplate, _ := x509.ParseCertificate(f.rootDER)
	issuerTemplate, _ := x509.ParseCertificate(f.issuerDER)
	// Deliberately invalid custody fixture: two distinct certificates carrying
	// the same ordinary ephemeral key must not bring the root key online.
	rootTemplate.PublicKey = f.key.Public()
	rootTemplate.SubjectKeyId = nil
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, f.key.Public(), f.key)
	if err != nil {
		t.Fatal("shared-key fixture root failed")
	}
	root, _ := x509.ParseCertificate(rootDER)
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, root, f.key.Public(), f.key)
	if err != nil {
		t.Fatal("shared-key fixture intermediate failed")
	}
	if _, err := enrollmentissuer.New(issuerDER, rootDER, f.key, hash(issuerDER), now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
		t.Fatal("offline root key was accepted as an online intermediate", err)
	}
	for _, corruptIssuer := range []bool{false, true} {
		issuerDER, rootDER := bytes.Clone(f.issuerDER), bytes.Clone(f.rootDER)
		if corruptIssuer {
			issuerDER[len(issuerDER)-1] ^= 1
		} else {
			rootDER[len(rootDER)-1] ^= 1
		}
		if _, err := enrollmentissuer.New(issuerDER, rootDER, f.key, hash(issuerDER), now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("invalid authority signature was accepted", err)
		}
	}
}

type unsupportedSigner struct{}

func (*unsupportedSigner) Public() crypto.PublicKey {
	panic("unsupported signer must never be invoked")
}
func (*unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("unsupported signer must never be invoked")
}

func TestConstructorRejectsInvalidMaterial(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	malformed := ed25519.PrivateKey(bytes.Clone(f.key))
	malformed[0] ^= 1 // Public suffix agrees, but the supplied private seed does not.
	var typedNil *unsupportedSigner
	for name, key := range map[string]crypto.Signer{
		"nil": nil, "typed nil external": typedNil, "external signer": &unsupportedSigner{},
		"nil Ed25519": ed25519.PrivateKey(nil), "short key": ed25519.PrivateKey(make([]byte, 63)),
		"long key": ed25519.PrivateKey(make([]byte, 65)), "wrong key": wrongKey, "inconsistent private key": malformed,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := enrollmentissuer.New(f.issuerDER, f.rootDER, key, f.intent.IssuerFingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
				t.Fatal("invalid signer accepted", err)
			}
		})
	}
	for _, der := range [][]byte{nil, []byte("not DER"), append(bytes.Clone(f.issuerDER), 0), make([]byte, enrollmentcrypto.MaxCertificateBytes+1)} {
		if _, err := enrollmentissuer.New(der, f.rootDER, f.key, f.intent.IssuerFingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("invalid intermediate bytes accepted", err)
		}
		if _, err := enrollmentissuer.New(f.issuerDER, der, f.key, f.intent.IssuerFingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("invalid root bytes accepted", err)
		}
	}
	for _, fingerprint := range []string{"", strings.ToUpper(f.intent.IssuerFingerprint), strings.Repeat("1", 64)} {
		if _, err := enrollmentissuer.New(f.issuerDER, f.rootDER, f.key, fingerprint, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("untrusted fingerprint accepted", err)
		}
	}
	for _, at := range []time.Time{{}, time.Unix(0, 0), time.Unix(253402300800, 0)} {
		if _, err := enrollmentissuer.New(f.issuerDER, f.rootDER, f.key, f.intent.IssuerFingerprint, at); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("invalid constructor clock accepted", err)
		}
	}
}

func TestSignRejectsInvalidIntents(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	i := f.issuer(t)
	for name, edit := range map[string]func(*enrollmentcrypto.Intent){
		"issuer substitution":         func(i *enrollmentcrypto.Intent) { i.IssuerFingerprint = strings.Repeat("1", 64) },
		"request subject as identity": func(i *enrollmentcrypto.Intent) { i.DeviceID = "arbitrary CSR subject" },
		"wrong template":              func(i *enrollmentcrypto.Intent) { i.TemplateVersion = "other" },
		"unknown profile":             func(i *enrollmentcrypto.Intent) { i.Profile = "unknown" },
		"noncanonical origin":         func(i *enrollmentcrypto.Intent) { i.Origin += "/" },
		"wrong collection profile":    func(i *enrollmentcrypto.Intent) { i.CollectionProfile = "other" },
		"wrong generation":            func(i *enrollmentcrypto.Intent) { i.KeyGeneration = 2 },
		"zero serial":                 func(i *enrollmentcrypto.Intent) { i.SerialHex = strings.Repeat("0", 32) },
		"oversize serial":             func(i *enrollmentcrypto.Intent) { i.SerialHex += "01" },
		"uppercase serial":            func(i *enrollmentcrypto.Intent) { i.SerialHex = strings.Repeat("AB", 16) },
		"future leaf":                 func(i *enrollmentcrypto.Intent) { i.NotBefore = now.Unix() + 1 },
		"expired leaf":                func(i *enrollmentcrypto.Intent) { i.NotAfter = now.Unix() },
		"reversed interval":           func(i *enrollmentcrypto.Intent) { i.NotAfter = i.NotBefore },
		"unbounded lifetime": func(i *enrollmentcrypto.Intent) {
			i.NotAfter = i.NotBefore + enrollmentcrypto.MaxCertificateLifetimeSeconds + 1
		},
		"before issuer":            func(i *enrollmentcrypto.Intent) { i.NotBefore = now.Add(-time.Hour - time.Second).Unix() },
		"malformed key":            func(i *enrollmentcrypto.Intent) { i.PublicKeyDERBase64 = "invalid" },
		"wrong public key binding": func(i *enrollmentcrypto.Intent) { i.KeyFingerprint = strings.Repeat("1", 64) },
		"missing claim hash":       func(i *enrollmentcrypto.Intent) { i.ClaimHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			intent := f.intent
			edit(&intent)
			result, err := i.Sign(context.Background(), intent, now)
			if !errors.Is(err, enrollmentissuer.ErrIntent) || result.Valid() || len(result.DER()) != 0 {
				t.Fatal("invalid intent issued", err)
			}
		})
	}
	short := makeFixture(t, nil, nil, func(c *x509.Certificate) { c.NotAfter = now.Add(time.Hour) })
	if _, err := short.issuer(t).Sign(context.Background(), short.intent, now); !errors.Is(err, enrollmentissuer.ErrIntent) {
		t.Fatal("leaf escaped issuer lifetime", err)
	}
	if _, err := i.Sign(context.Background(), f.intent, time.Time{}); !errors.Is(err, enrollmentissuer.ErrIntent) {
		t.Fatal("invalid signing clock accepted", err)
	}
}

func TestValidityBoundariesAndRevalidation(t *testing.T) {
	f := makeFixture(t, nil, nil, func(c *x509.Certificate) { c.NotAfter = now.Add(time.Hour) })
	f.intent.NotBefore = now.Unix()
	f.intent.NotAfter = now.Add(time.Hour).Unix()
	i := f.issuer(t)
	for _, at := range []time.Time{now, now.Add(time.Hour - time.Nanosecond)} {
		if _, err := i.Sign(context.Background(), f.intent, at); err != nil {
			t.Fatal("valid inclusive start/exclusive end boundary rejected", err)
		}
	}
	for _, at := range []time.Time{now.Add(-time.Hour - time.Nanosecond), now.Add(time.Hour)} {
		if _, err := i.Sign(context.Background(), f.intent, at); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
			t.Fatal("issuer time was not revalidated", err)
		}
	}
	if _, err := i.Sign(context.Background(), f.intent, now.Add(-time.Nanosecond)); !errors.Is(err, enrollmentissuer.ErrIntent) {
		t.Fatal("future leaf boundary accepted", err)
	}
	long := makeFixture(t, nil, nil, nil)
	long.intent.NotBefore = now.Unix()
	long.intent.NotAfter = long.intent.NotBefore + enrollmentcrypto.MaxCertificateLifetimeSeconds
	if _, err := long.issuer(t).Sign(context.Background(), long.intent, now); err != nil {
		t.Fatal("exact maximum permitted lifetime rejected", err)
	}
}

func TestPrivateCopiesAndConcurrentHandles(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	i := f.issuer(t)
	baseline, err := i.Sign(context.Background(), f.intent, now)
	if err != nil {
		t.Fatal(err)
	}
	copyHandle := *i
	if i.Fingerprint() != f.intent.IssuerFingerprint || !bytes.Equal(i.IssuerDER(), f.issuerDER) || !bytes.Equal(i.RootDER(), f.rootDER) {
		t.Fatal("public metadata mismatch")
	}
	for _, raw := range [][]byte{f.key, f.issuerDER, f.rootDER, i.IssuerDER(), i.RootDER(), baseline.DER()} {
		clear(raw)
	}
	var wg sync.WaitGroup
	errorsFound := make(chan error, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			handle := i
			if n%2 == 1 {
				handle = &copyHandle
			}
			result, err := handle.Sign(context.Background(), f.intent, now)
			if err != nil || !bytes.Equal(result.DER(), baseline.DER()) {
				errorsFound <- errors.New("private copy or deterministic concurrent signing failed")
			}
		}(n)
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestDiagnosticsRedactPointerAndValue(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	i := f.issuer(t)
	for _, value := range []any{i, *i, enrollmentissuer.Issuer{}, &enrollmentissuer.Issuer{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			if got := fmt.Sprintf(format, value); got != "enrollmentissuer.Issuer{material:redacted}" {
				t.Fatal("handle formatting was not redacted")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"materialRedacted":true}` {
			t.Fatal("handle JSON was not redacted")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("fixture handle", "issuer", value)
		if !strings.Contains(log.String(), "material:redacted") || strings.Contains(log.String(), f.intent.IssuerFingerprint) || strings.Contains(log.String(), base64.StdEncoding.EncodeToString(f.key)) {
			t.Fatal("handle log was not redacted")
		}
	}
	if raw, err := i.MarshalText(); err != nil || string(raw) != i.String() {
		t.Fatal("handle text was not redacted")
	}
	if i.GoString() != i.String() {
		t.Fatal("GoString was not redacted")
	}
}

type cancelAtCheck struct {
	context.Context
	checks, at int
}

func (c *cancelAtCheck) Err() error {
	c.checks++
	if c.checks >= c.at {
		return context.Canceled
	}
	return nil
}

func TestCancellationAndZeroHandlesFailClosed(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	i := f.issuer(t)
	for check := 1; check <= 4; check++ {
		ctx := &cancelAtCheck{Context: context.Background(), at: check}
		result, err := i.Sign(ctx, f.intent, now)
		if !errors.Is(err, context.Canceled) || result.Valid() || len(result.DER()) != 0 {
			t.Fatal("canceled signing returned a credential", err)
		}
	}
	if _, err := i.Sign(nil, f.intent, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
		t.Fatal("nil context accepted", err)
	}
	var nilIssuer *enrollmentissuer.Issuer
	for _, handle := range []*enrollmentissuer.Issuer{nilIssuer, {}} {
		result, err := handle.Sign(context.Background(), f.intent, now)
		if !errors.Is(err, enrollmentissuer.ErrConfiguration) || result.Valid() || handle.Fingerprint() != "" || len(handle.IssuerDER()) != 0 || len(handle.RootDER()) != 0 {
			t.Fatal("uninitialized handle did not fail closed")
		}
	}
}

type processFixture struct {
	Issuer, Root, Key []byte
	Intent            enrollmentcrypto.Intent
}

func TestIssuerFreshProcessHelper(t *testing.T) {
	if os.Getenv("TRACEBOLT_ISSUER_TEST_CHILD") != "1" {
		return
	}
	var input processFixture
	if json.NewDecoder(io.LimitReader(os.Stdin, 64<<10)).Decode(&input) != nil {
		os.Exit(10)
	}
	i, err := enrollmentissuer.New(input.Issuer, input.Root, ed25519.PrivateKey(input.Key), input.Intent.IssuerFingerprint, now)
	if err != nil {
		os.Exit(11)
	}
	result, err := i.Sign(context.Background(), input.Intent, now)
	if err != nil {
		os.Exit(12)
	}
	if _, err := os.Stdout.Write(result.DER()); err != nil {
		os.Exit(13)
	}
	os.Exit(0)
}

func TestExactDERAfterFreshProcessReconstruction(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	baseline, err := f.issuer(t).Sign(context.Background(), f.intent, now)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(processFixture{Issuer: f.issuerDER, Root: f.rootDER, Key: f.key, Intent: f.intent})
	if err != nil {
		t.Fatal("ephemeral subprocess fixture encoding failed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestIssuerFreshProcessHelper$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_ISSUER_TEST_CHILD=1")
	// Ephemeral material travels only over private stdin, never argv, an
	// environment variable, a fixture file, test failure output or a log.
	cmd.Stdin = bytes.NewReader(input)
	var output, diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatal("fresh-process fixture execution failed")
	}
	if !bytes.Equal(baseline.DER(), output.Bytes()) {
		t.Fatal("certificate DER changed after actual process reconstruction")
	}
}

func TestPublicAuthorityValidationNeedsNoSigningKey(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	if err := enrollmentissuer.ValidatePublicAuthority(f.issuerDER, f.rootDER, hash(f.issuerDER), now); err != nil {
		t.Fatal("valid public bootstrap rejected")
	}
	if err := enrollmentissuer.ValidatePublicAuthority(f.issuerDER, f.rootDER, strings.Repeat("1", 64), now); err == nil {
		t.Fatal("wrong pinned issuer accepted")
	}
	if err := enrollmentissuer.ValidatePublicAuthority(f.issuerDER, nil, hash(f.issuerDER), now); err == nil {
		t.Fatal("missing explicit root accepted")
	}
	if err := enrollmentissuer.ValidatePublicAuthority(f.issuerDER, f.rootDER, hash(f.issuerDER), time.Time{}); err == nil {
		t.Fatal("invalid trusted time accepted")
	}
}
