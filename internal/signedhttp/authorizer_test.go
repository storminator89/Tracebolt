package signedhttp

import (
	"errors"
	"net/http"
	"testing"

	"localrmm/internal/lantrust"
)

type delegatedAuthorizer struct {
	registry *lantrust.Registry
	calls    int
	err      error
}

func (a *delegatedAuthorizer) AuthorizePublicCertificate(raw []byte) (lantrust.Agent, error) {
	a.calls++
	if a.err != nil {
		return lantrust.Agent{}, a.err
	}
	return a.registry.AuthorizePublicCertificate(raw)
}
func TestPublicCertificateAuthorizerRetainsBothFreshLookups(t *testing.T) {
	f := makeFixture(t, nil)
	a := &delegatedAuthorizer{registry: f.registry}
	v, err := New(Config{Origin: testOrigin, Registry: a})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(request(t, f))
	if err != nil || got.Agent != f.agent || a.calls != 2 {
		t.Fatal("public adapter changed authorization checks", err)
	}
	a.err = lantrust.ErrRegistryUnavailable
	if _, err = v.Verify(request(t, f)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("storage error became unauthorized", err)
	}
}
func TestNilPublicCertificateAuthorizerAndZeroVerifierFailClosed(t *testing.T) {
	var concrete *lantrust.Registry
	var adapter *delegatedAuthorizer
	for _, authorizer := range []PublicCertificateAuthorizer{nil, concrete, adapter} {
		if _, err := New(Config{Origin: testOrigin, Registry: authorizer}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("nil authorizer accepted")
		}
	}
	r, _ := http.NewRequest(http.MethodPost, testOrigin+Path, nil)
	for _, v := range []*Verifier{nil, {}} {
		if _, err := v.Verify(r); !errors.Is(err, ErrRequest) {
			t.Fatal("zero verifier accepted")
		}
	}
}
