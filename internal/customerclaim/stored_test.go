package customerclaim

import (
	"strings"
	"testing"
)

// The constants are independently computed from the v1 length-prefixed
// transcript, not from the implementation under test. They pin prior bytes.
func TestMetadataDigestGoldenV1(t *testing.T) {
	m := Metadata{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64), ClaimID: "claim_" + strings.Repeat("4", 32), RequestID: "request_" + strings.Repeat("5", 32), KeyFingerprint: strings.Repeat("b", 64), CSRHash: strings.Repeat("c", 64)}
	claim, comparison := metadataDigests(m)
	if claim != "10b12e3da991df1fecba0feb2ff50ee1df49c9302b1addd46053bd54f96fe7c0" || comparison != "3a06dc97672a0af326469553a5bf3d85" {
		t.Fatalf("v1 transcript bytes changed: %s %s", claim, comparison)
	}
}
