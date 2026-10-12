package windowspackage

import (
	"bytes"
	"context"
	"testing"

	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowssoftwarejob"
)

func preparedFixture() ([]byte, job.Selection) {
	b := make([]byte, 1024)
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	return b, job.Selection{SHA256: actionpermit.Digest(b), Size: int64(len(b)), ProductCode: "{11111111-2222-3333-4444-555555555555}", PackageCode: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", Version: "1.2.3", Architecture: "amd64", Name: "Fixture only", TermsReviewDigest: actionpermit.Digest([]byte("terms")), ReviewReference: "Fixture review"}
}
func TestPreparedMSICustodyRejectsChangedOrWrongKindBytes(t *testing.T) {
	b, s := preparedFixture()
	if ValidatePreparedMSIBytes(b, s) != nil {
		t.Fatal("fixture invalid")
	}
	for _, change := range []func([]byte, *job.Selection){func(b []byte, s *job.Selection) { b[511]++ }, func(b []byte, s *job.Selection) { s.Size++ }, func(b []byte, s *job.Selection) { s.Architecture = "arm64" }, func(b []byte, s *job.Selection) { b[0] = 'M'; s.SHA256 = actionpermit.Digest(b) }, func(b []byte, s *job.Selection) { s.TermsReviewDigest = "" }, func(b []byte, s *job.Selection) { s.ProductCode = "../package.msi" }} {
		copy := bytes.Clone(b)
		selection := s
		change(copy, &selection)
		if ValidatePreparedMSIBytes(copy, selection) == nil {
			t.Fatal("changed input admitted")
		}
	}
}

type custodyPin struct {
	checks, closes int
	fail           bool
}

func (p *custodyPin) Verify(context.Context, PreparedMSIReceipt) error {
	p.checks++
	if p.fail {
		return ErrPackage
	}
	return nil
}
func (*custodyPin) PinnedPath() string { return "fixed protected fixture" }
func (p *custodyPin) Close() error     { p.closes++; return nil }
func TestCustodyLeaseNeverReopensAfterClose(t *testing.T) {
	pin := &custodyPin{}
	p := &PreparedMSI{pin: pin}
	if p.Verify(context.Background()) != nil || p.Path() == "" {
		t.Fatal("missing pin")
	}
	if p.Close() != nil || p.Close() != nil || pin.closes != 1 {
		t.Fatal("duplicate close")
	}
	if p.Verify(context.Background()) == nil || p.Path() != "" || pin.checks != 1 {
		t.Fatal("closed lease reused")
	}
}
