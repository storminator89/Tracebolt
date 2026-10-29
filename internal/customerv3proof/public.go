package customerv3proof

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/enrollmentcrypto"
)

// SigningMessagePublic prepares the exact existing v3 possession transcript
// without exposing internal actor/review data to a device. local and claimHash
// must come from the protected original profile, key and claim. A well-formed
// but wrong local claimHash cannot be detected from the projection: the server
// compares the resulting proof to its exact committed original intent.
// Authenticated manager identity, current authority, challenge one-use,
// response guarding and native local consent remain caller obligations.
// Activation additionally requires the separate customerissuance public leaf
// verifier and actual protected lifecycle authority. This function neither signs
// nor starts a service.
func SigningMessagePublic(p customerissuance.PublicIntent, local customerissuance.LocalPublicBinding, claimHash string, purpose Purpose, challenge customerclaim.Context, requestID, certificateHash string, now time.Time) ([]byte, error) {
	if customerissuance.MatchLocalPublic(p, local, now) != nil || !enrollmentcrypto.ValidHash(claimHash) || !customerclaim.ValidChallengeContext(challenge, now) || !enrollmentcrypto.ValidID(requestID, "request_") {
		return nil, ErrProof
	}
	if purpose != Credential && purpose != Activation || purpose == Credential && certificateHash != "" || purpose == Activation && !enrollmentcrypto.ValidHash(certificateHash) {
		return nil, ErrProof
	}
	if challenge.ManagerID != p.ManagerID || challenge.CustomerID != p.CustomerID || challenge.InstallerProfileID != p.InstallerProfileID || challenge.ClaimID != p.ClaimID || challenge.Origin != p.Origin || challenge.AgentOrigin != p.AgentOrigin || challenge.IssuerFingerprint != p.IssuerFingerprint {
		return nil, ErrProof
	}
	fields := []string{"Tracebolt customer Windows v3 credential possession v1", string(purpose), p.IntentDigest, p.ManagerID, p.CustomerID, p.InstallerProfileID, p.ClaimID, claimHash, p.KeyFingerprint, p.Origin, p.AgentOrigin, p.IssuerFingerprint, requestID, challenge.Challenge, strconv.FormatInt(challenge.ExpiresAt, 10), certificateHash}
	var out bytes.Buffer
	for _, value := range fields {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(value)))
		out.WriteString(value)
	}
	return out.Bytes(), nil
}
