package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const RetirementVersion = "tracebolt.windows-selected-update-retirement.v1"
const ReusableRecordVersion = "tracebolt.windows-selected-update-record.v2"
const MaxRecentJobs = 8

// Retirement is metadata-only authority to compact one exact successful job.
// It cannot substitute for installation approval or extend the original grant.
type RetirementPermit struct {
	Version        string    `json:"version"`
	Binding        Binding   `json:"binding"`
	JobID          string    `json:"jobId"`
	Selection      Selection `json:"selection"`
	Occurrence     uint64    `json:"occurrence,string"`
	EnvelopeDigest string    `json:"envelopeDigest"`
	ResultDigest   string    `json:"resultDigest"`
	ActorID        string    `json:"actorId"`
	IssuedAt       int64     `json:"issuedAt"`
	ExpiresAt      int64     `json:"expiresAt"`
}

func (p RetirementPermit) Validate() error {
	if p.Version != RetirementVersion || !ValidBinding(p.Binding) || !enrollmentcrypto.ValidID(p.JobID, "update_") || !ValidSelection(p.Selection) || p.Occurrence == 0 || !actionpermit.ValidDigest(p.EnvelopeDigest) || !actionpermit.ValidDigest(p.ResultDigest) || !enrollmentcrypto.ValidID(p.ActorID, "operator_") || !validTime(p.IssuedAt) || !validTime(p.ExpiresAt) || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 300 {
		return ErrInvalid
	}
	return nil
}

type RetirementReport struct {
	Version         string    `json:"version"`
	Binding         Binding   `json:"binding"`
	JobID           string    `json:"jobId"`
	Selection       Selection `json:"selection"`
	Occurrence      uint64    `json:"occurrence,string"`
	ReferenceDigest string    `json:"referenceDigest"`
	EnvelopeDigest  string    `json:"envelopeDigest"`
	ResultDigest    string    `json:"resultDigest"`
	ReleaseDigest   string    `json:"releaseDigest"`
	IssuedAt        int64     `json:"issuedAt"`
	ExpiresAt       int64     `json:"expiresAt"`
}

func (r RetirementReport) Validate() error {
	if r.Version != RetirementVersion || !ValidBinding(r.Binding) || !enrollmentcrypto.ValidID(r.JobID, "update_") || !ValidSelection(r.Selection) || r.Occurrence == 0 || !validTime(r.IssuedAt) || !validTime(r.ExpiresAt) || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > 300 {
		return ErrInvalid
	}
	for _, d := range []string{r.ReferenceDigest, r.EnvelopeDigest, r.ResultDigest, r.ReleaseDigest} {
		if !actionpermit.ValidDigest(d) {
			return ErrInvalid
		}
	}
	return nil
}

type retirementEnvelope struct {
	Permit    RetirementPermit `json:"permit"`
	Signature string           `json:"signature"`
}
type retirementReportEnvelope struct {
	Report    RetirementReport `json:"report"`
	Signature string           `json:"signature"`
}

func retirementMessage(v any, domain string) []byte {
	b, _ := json.Marshal(v)
	return append([]byte(domain+"\x00"), b...)
}
func validPrivateKey(k ed25519.PrivateKey, pin string) bool {
	return len(k) == ed25519.PrivateKeySize && bytes.Equal(k, ed25519.NewKeyFromSeed(k[:32])) && actionpermit.Digest(k.Public().(ed25519.PublicKey)) == pin
}
func SignRetirement(p RetirementPermit, k ed25519.PrivateKey) ([]byte, error) {
	if p.Validate() != nil || !validPrivateKey(k, p.Binding.KeyID) {
		return nil, ErrInvalid
	}
	return json.Marshal(retirementEnvelope{p, base64.RawStdEncoding.EncodeToString(ed25519.Sign(k, retirementMessage(p, "Tracebolt cached WUA retirement permit v1")))})
}
func VerifyRetirement(raw []byte, k ed25519.PublicKey) (RetirementPermit, error) {
	var e retirementEnvelope
	if !keyvalidation.Ed25519(k) || canonical(raw, &e, MaxRelayBytes) != nil || e.Permit.Validate() != nil || e.Permit.Binding.KeyID != actionpermit.Digest(k) {
		return RetirementPermit{}, ErrInvalid
	}
	s, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(s) != e.Signature || !ed25519.Verify(k, retirementMessage(e.Permit, "Tracebolt cached WUA retirement permit v1"), s) {
		return RetirementPermit{}, ErrAuthority
	}
	return e.Permit, nil
}
func SignRetirementReport(r RetirementReport, k ed25519.PrivateKey) ([]byte, error) {
	if r.Validate() != nil || !validPrivateKey(k, r.Binding.ExecutorKeyID) {
		return nil, ErrInvalid
	}
	return json.Marshal(retirementReportEnvelope{r, base64.RawStdEncoding.EncodeToString(ed25519.Sign(k, retirementMessage(r, "Tracebolt cached WUA retirement report v1")))})
}
func VerifyRetirementReport(raw []byte, k ed25519.PublicKey) (RetirementReport, error) {
	var e retirementReportEnvelope
	if !keyvalidation.Ed25519(k) || canonical(raw, &e, MaxRelayBytes) != nil || e.Report.Validate() != nil || e.Report.Binding.ExecutorKeyID != actionpermit.Digest(k) {
		return RetirementReport{}, ErrInvalid
	}
	s, err := base64.RawStdEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawStdEncoding.EncodeToString(s) != e.Signature || !ed25519.Verify(k, retirementMessage(e.Report, "Tracebolt cached WUA retirement report v1"), s) {
		return RetirementReport{}, ErrAuthority
	}
	return e.Report, nil
}

type RetiredJob struct {
	Occurrence       uint64    `json:"occurrence,string"`
	JobID            string    `json:"jobId"`
	Selection        Selection `json:"selection"`
	Result           Result    `json:"result"`
	ResultDigest     string    `json:"resultDigest"`
	RetirementDigest string    `json:"retirementDigest"`
	RequestedAt      int64     `json:"requestedAt"`
	ApprovedAt       int64     `json:"approvedAt"`
	ClaimedAt        int64     `json:"claimedAt"`
	RetiredAt        int64     `json:"retiredAt"`
}

func (j RetiredJob) Validate() error {
	if j.Occurrence == 0 || !enrollmentcrypto.ValidID(j.JobID, "update_") || !ValidSelection(j.Selection) || j.Result.Validate() != nil || j.Result.Outcome != "succeeded" || j.Result.JobID != j.JobID || !actionpermit.ValidDigest(j.ResultDigest) || !actionpermit.ValidDigest(j.RetirementDigest) || !validTime(j.RetiredAt) || j.RetiredAt < j.Result.CompletedAt {
		return ErrIntegrity
	}
	return nil
}
func retiredChain(previous string, j RetiredJob) string {
	return digest(struct {
		Previous string
		Job      RetiredJob
	}{previous, j})
}
