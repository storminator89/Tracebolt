package windowssecuritycoverage

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture() Request {
	b := strings.Repeat("a", 64)
	return Request{Consent: Consent{ConsentVersion, Scope, b, strings.Repeat("b", 32), true}, SenderBinding: b, GenerationID: "sample_" + strings.Repeat("c", 32), CollectedAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}
func TestCanonicalCoverageAndFiniteUnknowns(t *testing.T) {
	r := fixture()
	s := Empty(r, ErrUnavailable.Error())
	count := uint32(1)
	name := "Example Antivirus"
	s.Antivirus = Antivirus{Quality: "observed", ReportedCount: &count, Rows: []Product{{0, &name, "snoozed", "out-of-date"}}}
	s.TPM = tpmInfo(2)
	b, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Snapshot){func(v *Snapshot) { v.Antivirus.Rows = nil }, func(v *Snapshot) { v.Antivirus.Rows[0].State = "protected" }, func(v *Snapshot) { v.TPM.Version = "ready" }, func(v *Snapshot) { v.TPM.Presence = "not-found" }, func(v *Snapshot) { v.Antivirus.ReportedCount = nil }} {
		copy, _ := Decode(b)
		mutate(&copy)
		if Validate(copy) == nil {
			t.Fatal("invalid metadata admitted")
		}
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), '\n'), bytes.Replace(b, []byte(`"tpm":`), []byte(`"recoveryKey":"secret","tpm":`), 1)} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("noncanonical or extra payload accepted")
		}
	}
	for _, name := range []string{"", "unsafe\nlabel", strings.Repeat("界", 129), "label\u202eexe"} {
		if validName(name) {
			t.Fatal("invalid name", name)
		}
	}
	unknown := tpmInfo(99)
	if !validTPM(unknown) || unknown.Presence != "present" || unknown.Version != "unknown" || unknown.Quality != "partial" {
		t.Fatal("unknown version invented")
	}
}
func TestCoverageSourceIndependenceAndDisabledNoRead(t *testing.T) {
	r := fixture()
	calls := 0
	a := func(context.Context) (Antivirus, error) { calls++; return Antivirus{}, ErrDenied }
	p := func(context.Context) (TPM, error) { calls++; return tpmInfo(2), nil }
	s, e := CollectWithSources(context.Background(), r, a, p)
	if e != nil || s.Antivirus.Quality != "denied" || s.TPM.Version != "2.0" {
		t.Fatal("provider erased sibling", e)
	}
	r.Consent.Enabled = false
	if _, e = CollectWithSources(context.Background(), r, a, p); e != ErrDisabled || calls != 2 {
		t.Fatal("default off opened source")
	}
}
func TestCoverageFitPreservesCountAgeAndGrant(t *testing.T) {
	s := Empty(fixture(), ErrUnavailable.Error())
	count := uint32(MaxProducts)
	name := strings.Repeat("界", 128)
	s.Antivirus = Antivirus{Quality: "observed", ReportedCount: &count, Rows: []Product{}}
	for i := 0; i < MaxProducts; i++ {
		s.Antivirus.Rows = append(s.Antivirus.Rows, Product{i, &name, "on", "up-to-date"})
	}
	// Work within the total model bound while exercising actual whole-row fitting.
	for i := range s.Antivirus.Rows {
		n := strings.Repeat("x", 128)
		s.Antivirus.Rows[i].Name = &n
	}
	raw, e := Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	got, e := FitBudget(s, len(raw)-600)
	if e != nil || !got.Antivirus.Truncated || *got.Antivirus.ReportedCount != count || got.GrantID != s.GrantID || !got.CollectedAt.Equal(s.CollectedAt) || Validate(got) != nil {
		t.Fatal("budget lost source binding", e)
	}
}
func TestCoverageNativeReadOnlySourceContract(t *testing.T) {
	b, e := os.ReadFile("native_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, v := range []string{`"Initialize"`, `"Count"`, `"Item"`, `"ProductName"`, `"ProductState"`, `"SignatureStatus"`, `"Tbsi_GetDeviceInfo"`, `os.ProductType != 1`} {
		if !strings.Contains(s, v) {
			t.Fatal("missing fixed source", v)
		}
	}
	for _, v := range []string{`"RemediationPath"`, `"ProductGuid"`, `"ProductStateTimestamp"`, `"SetDefaultProduct"`, `"Tbsip_Submit_Command"`, `"GetProtectionStatus"`, `"Win32_Tpm"`} {
		if strings.Contains(s, v) {
			t.Fatal("unapproved native source", v)
		}
	}
}

func TestEscapedProductNamesFitBeforeEnvelopeEncoding(t *testing.T) {
	s := Empty(fixture(), ErrUnavailable.Error())
	n := uint32(MaxProducts)
	name := strings.Repeat("<", MaxProductNameUnits)
	s.Antivirus = Antivirus{Quality: "observed", ReportedCount: &n, Rows: []Product{}}
	for i := 0; i < MaxProducts; i++ {
		s.Antivirus.Rows = append(s.Antivirus.Rows, Product{i, &name, "on", "up-to-date"})
	}
	fit, e := FitBudget(s, MaxBytes)
	if e != nil || Validate(fit) != nil || !fit.Antivirus.Truncated || *fit.Antivirus.ReportedCount != n {
		t.Fatal("native text bound lost useful rows", e)
	}
}
