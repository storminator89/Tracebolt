package enrollmentstate

import (
	"encoding/hex"
	"net"
	"net/url"
	"strconv"
	"strings"

	"localrmm/internal/enrollmentcrypto"
)

func validHex(s string, n int) bool {
	if len(s) != n || s == strings.Repeat("0", n) {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validID(s, prefix string) bool {
	return strings.HasPrefix(s, prefix+"_") && validHex(strings.TrimPrefix(s, prefix+"_"), 32)
}
func validHash(s string) bool     { return validHex(s, 64) }
func validTime(t int64) bool      { return t > 0 && t <= MaxTimestamp }
func validPlatform(s string) bool { return s == "linux" || s == "windows" || s == "darwin" }

// Origins are exact profile-bound authorities: no path, credentials, query, fragment,
// escapes, Unicode, default-port alias, case alias, or IPv6 zone identifier.
func validOrigin(s, profile string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ToLower(s) != s || strings.ContainsAny(s, "%\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || (profile == "tls" && u.Scheme != "https" || profile == "http-test" && u.Scheme != "http") || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != s {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(host, ".") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.String() != host {
			return false
		}
	} else {
		if len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || (profile == "tls" && n == 443 || profile == "http-test" && n == 80) || strconv.Itoa(n) != port {
			return false
		}
		if u.Host != net.JoinHostPort(host, port) {
			return false
		}
	} else if strings.Contains(u.Host, ":") && u.Host != "["+host+"]" {
		return false
	}
	return true
}

func validBinding(b Binding) bool {
	return validID(b.InstanceID, "manager") && (b.Profile == "tls" || b.Profile == "http-test") && validOrigin(b.Origin, b.Profile) && b.CollectionProfile == "basic-readonly-v1" && validHash(b.IssuerFingerprint)
}

func validateConfig(c Config) error {
	if !validBinding(c.Binding) || c.InvitationTTL < 1 || c.InvitationTTL > MaxInvitationTTL || c.PendingTTL < 1 || c.PendingTTL > MaxPendingTTL || c.RecordLimit < 1 || c.RecordLimit > MaxRecords || c.InvitationLimit < 1 || c.InvitationLimit > MaxInvitations || c.PendingLimit < 1 || c.PendingLimit > MaxPending || c.InvitationLimit > c.RecordLimit || c.PendingLimit > c.RecordLimit {
		return ErrInvalid
	}
	return nil
}

func validateCreate(c CreateCommand) error {
	if !validID(c.InvitationID, "invite") || !validID(c.RequestID, "request") || !validHash(c.InvitationHash) || !validPlatform(c.Platform) || !validTime(c.Now) || c.Now > MaxTimestamp-MaxPendingTTL-MaxInvitationTTL {
		return ErrInvalid
	}
	return nil
}

func validateControl(c Control) error {
	if !validID(c.InvitationID, "invite") || !validID(c.RequestID, "request") || c.ExpectedRevision < 1 || c.ExpectedRevision > MaxRevision || !validTime(c.Now) {
		return ErrInvalid
	}
	return nil
}

func validateClaim(c ClaimCommand) error {
	if validateControl(c.Control) != nil || !validID(c.ClaimID, "claim") {
		return ErrInvalid
	}
	return nil
}

func validateApprove(c ApproveCommand) error {
	if validateControl(c.Control) != nil || !validID(c.DeviceID, "agent") || !validHash(c.KeyFingerprint) {
		return ErrInvalid
	}
	return nil
}

func validSerial(s string) bool {
	// A canonical 128-bit positive serial fits RFC 5280's 20-octet ceiling.
	return validHex(s, 32)
}

func validateIntent(c IntentCommand) error {
	if validateControl(c.Control) != nil || !validID(c.IntentID, "intent") || !validSerial(c.SerialHex) || c.TemplateVersion != TemplateVersion || !validTime(c.NotBefore) || !validTime(c.NotAfter) || c.NotAfter <= c.NotBefore || c.NotAfter-c.NotBefore > MaxCertificateTTL {
		return ErrInvalid
	}
	return nil
}

func stage(s State) int {
	switch s {
	case Created:
		return 1
	case ClaimedPending:
		return 2
	case Approved:
		return 3
	case IssuanceIntent:
		return 4
	case Issued:
		return 5
	case Activated:
		return 6
	}
	return 0
}
func terminal(s State) bool { return s == Expired || s == Canceled || s == Rejected || s == Revoked }
func deadline(s Snapshot) int64 {
	if s.State == Activated || s.Termination.From == Activated {
		return s.Intent.NotAfter
	}
	if (stage(s.State) >= 4 || stage(s.Termination.From) >= 4) && s.Intent.NotAfter < s.DeadlineAt {
		return s.Intent.NotAfter
	}
	return s.DeadlineAt
}

// ValidateSnapshot checks the complete public record, including state-specific
// presence and chronology. It cannot confer authority or restore private state.
func ValidateSnapshot(s Snapshot) error {
	if s.Version != SnapshotVersion || !validBinding(s.Binding) || !validID(s.InvitationID, "invite") || !validID(s.CreateRequestID, "request") || !validPlatform(s.Platform) || s.Revision < 1 || s.Revision > MaxRevision || !validTime(s.CreatedAt) || !validTime(s.DeadlineAt) || !validTime(s.UpdatedAt) || s.UpdatedAt < s.CreatedAt {
		return ErrInvalid
	}
	n := stage(s.State)
	if terminal(s.State) {
		n = stage(s.Termination.From)
		if n == 0 || !validID(s.Termination.RequestID, "request") || s.Termination.At != s.UpdatedAt || s.Termination.At < s.CreatedAt || s.Revision < uint64(n+1) {
			return ErrInvalid
		}
		if s.State == Rejected && n != 2 || s.State == Canceled && n >= 6 || s.State == Revoked && n < 3 || s.State == Expired && s.Termination.At < deadline(s) {
			return ErrInvalid
		}
	} else if s.Termination != (Termination{}) {
		return ErrInvalid
	}
	if n == 0 || s.Revision < uint64(n) {
		return ErrInvalid
	}
	requests := []string{s.CreateRequestID, s.Claim.RequestID, s.Approval.RequestID, s.Intent.RequestID, s.Issuance.RequestID, s.Activation.RequestID, s.Termination.RequestID}
	for i, request := range requests {
		if request == "" {
			continue
		}
		for _, prior := range requests[:i] {
			if prior == request {
				return ErrInvalid
			}
		}
	}
	last := s.CreatedAt
	if n >= 2 {
		c := s.Claim
		if !validID(c.ClaimID, "claim") || !validID(c.RequestID, "request") || !validHash(c.KeyFingerprint) || !validHash(c.CSRHash) || !validHash(c.ClaimHash) || !validHex(c.ComparisonCode, 32) || c.At < last || c.At >= s.CreatedAt+MaxInvitationTTL || s.DeadlineAt <= c.At || s.DeadlineAt-c.At > MaxPendingTTL {
			return ErrInvalid
		}
		code, err := enrollmentcrypto.ComparisonCode(s.Binding.InstanceID, s.InvitationID, c.ClaimID, c.KeyFingerprint)
		if err != nil || c.ComparisonCode != code {
			return ErrInvalid
		}
		last = c.At
	} else if s.Claim != (ClaimBinding{}) || s.DeadlineAt <= s.CreatedAt || s.DeadlineAt-s.CreatedAt > MaxInvitationTTL {
		return ErrInvalid
	}
	if n >= 3 {
		a := s.Approval
		if !validID(a.RequestID, "request") || !validID(a.DeviceID, "agent") || a.KeyFingerprint != s.Claim.KeyFingerprint || a.At < last || a.At >= s.DeadlineAt {
			return ErrInvalid
		}
		last = a.At
	} else if s.Approval != (Approval{}) {
		return ErrInvalid
	}
	if n >= 4 {
		i := s.Intent
		if !validID(i.IntentID, "intent") || !validID(i.RequestID, "request") || !validSerial(i.SerialHex) || i.TemplateVersion != TemplateVersion || i.DeviceID != s.Approval.DeviceID || i.KeyFingerprint != s.Claim.KeyFingerprint || i.At < last || i.At >= s.DeadlineAt || !validTime(i.NotBefore) || !validTime(i.NotAfter) || i.NotBefore > i.At || i.NotBefore < i.At-300 || i.NotAfter <= i.At || i.NotAfter-i.NotBefore > MaxCertificateTTL {
			return ErrInvalid
		}
		last = i.At
	} else if s.Intent != (Intent{}) {
		return ErrInvalid
	}
	if n >= 5 {
		i := s.Issuance
		if !validID(i.RequestID, "request") || !validHash(i.CertificateHash) || i.At < last || i.At >= s.DeadlineAt || i.At < s.Intent.NotBefore || i.At >= s.Intent.NotAfter {
			return ErrInvalid
		}
		last = i.At
	} else if s.Issuance != (Issuance{}) {
		return ErrInvalid
	}
	if n >= 6 {
		a := s.Activation
		if !validID(a.RequestID, "request") || a.At < last || a.At >= s.DeadlineAt || a.At >= s.Intent.NotAfter {
			return ErrInvalid
		}
		last = a.At
	} else if s.Activation != (Activation{}) {
		return ErrInvalid
	}
	if terminal(s.State) {
		if s.Termination.At < last {
			return ErrInvalid
		}
	} else if s.UpdatedAt != last {
		return ErrInvalid
	}
	return nil
}

func hashBytes(s string) [32]byte {
	var h [32]byte
	b, _ := hex.DecodeString(s)
	copy(h[:], b)
	return h
}
