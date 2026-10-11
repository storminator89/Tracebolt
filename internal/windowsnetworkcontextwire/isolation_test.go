package windowsnetworkcontextwire

import (
	"context"
	"localrmm/internal/windowsfullprocesseswire"
	"localrmm/internal/windowsfullserviceswire"
	"localrmm/internal/windowsfullsoftwarewire"
	"net/http"
	"testing"
	"time"
)

func TestNetworkContextProofCannotBePromotedFromOtherWindowsDomains(t *testing.T) {
	pair, registry := serviceWireFixture(t)
	v, e := New(Config{Origin: "http://fixture.invalid", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"services", "software"} {
		t.Run(kind, func(t *testing.T) {
			var r *http.Request
			var headers [][2]string
			if kind == "services" {
				r, e = windowsfullserviceswire.NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), []byte(`{}`))
				headers = [][2]string{{windowsfullserviceswire.CertificateHeader, CertificateHeader}, {windowsfullserviceswire.SequenceHeader, SequenceHeader}, {windowsfullserviceswire.SignedAtHeader, SignedAtHeader}, {windowsfullserviceswire.SignatureHeader, SignatureHeader}}
			} else {
				r, e = windowsfullsoftwarewire.NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), []byte(`{}`))
				headers = [][2]string{{windowsfullsoftwarewire.CertificateHeader, CertificateHeader}, {windowsfullsoftwarewire.SequenceHeader, SequenceHeader}, {windowsfullsoftwarewire.SignedAtHeader, SignedAtHeader}, {windowsfullsoftwarewire.SignatureHeader, SignatureHeader}}
			}
			if e != nil {
				t.Fatal(e)
			}
			for _, h := range headers {
				r.Header.Set(h[1], r.Header.Get(h[0]))
				r.Header.Del(h[0])
			}
			r.URL.Path = PathPrefix + "scope"
			if _, e := v.Verify(r); e == nil {
				t.Fatal("signature reused from", kind)
			}
		})
	}
}

func TestNetworkContextRejectsCompleteProcessProof(t *testing.T) {
	pair, registry := serviceWireFixture(t)
	verifier, e := New(Config{Origin: "http://fixture.invalid", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	r, e := windowsfullprocesseswire.NewSignedRequest(context.Background(), "http://fixture.invalid", pair, "scope", 1, time.Now().UTC(), []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	for _, h := range [][2]string{{windowsfullprocesseswire.CertificateHeader, CertificateHeader}, {windowsfullprocesseswire.SequenceHeader, SequenceHeader}, {windowsfullprocesseswire.SignedAtHeader, SignedAtHeader}, {windowsfullprocesseswire.SignatureHeader, SignatureHeader}} {
		r.Header.Set(h[1], r.Header.Get(h[0]))
		r.Header.Del(h[0])
	}
	r.URL.Path = PathPrefix + "scope"
	if _, e = verifier.Verify(r); e == nil {
		t.Fatal("process scope proof promoted")
	}
}
