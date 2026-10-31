package rustagent

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

// Public-only fixed fixture emitted by the actual Go issuer. No private key,
// current credential, endpoint state or production trust is present.
func TestPublicGoIssuedCredentialMatchesFixedContract(t *testing.T) {
	var fixture struct {
		Now            time.Time               `json:"now"`
		CertificateDER string                  `json:"certificateDer"`
		IssuerDER      string                  `json:"issuerDer"`
		Intent         enrollmentcrypto.Intent `json:"intent"`
	}
	raw, err := os.ReadFile("credential-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	der, err := base64.RawStdEncoding.Strict().DecodeString(fixture.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := base64.RawStdEncoding.Strict().DecodeString(fixture.IssuerDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollmentcrypto.VerifyIssued(der, issuer, fixture.Intent, fixture.Now); err != nil {
		t.Fatal("Go issuer fixed template was not preserved:", err)
	}
	wrong := fixture.Intent
	wrong.SerialHex = "09090909090909090909090909090909"
	if _, err := enrollmentcrypto.VerifyIssued(der, issuer, wrong, fixture.Now); err == nil {
		t.Fatal("fixed fixture lost its exact original serial")
	}
}
