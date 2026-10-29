package customerchallenge

import "localrmm/internal/customerclaim"

// IssueCredentialV3 creates a credential-retrieval-only challenge in the same
// bounded process-local pool and quotas as claim/status challenges. The caller
// must first resolve the original v3 claim, committed intent, key and exact
// verified certificate from current protected server state. IDs alone are not
// authority. No certificate hash or secret is needed from the client.
func (p *Pool) IssueCredentialV3(peer, customerID, profileID, claimID string) (customerclaim.Context, error) {
	return p.issue(peer, customerID, profileID, claimID, credentialV3Purpose)
}

// IssueActivationV3 creates an activation-only challenge in the same pool. The
// caller must independently resolve and authorize the exact protected v3
// intent, original key, issued certificate and lifecycle state before issuing.
// This function creates no credential, activation, identity or grant.
func (p *Pool) IssueActivationV3(peer, customerID, profileID, claimID string) (customerclaim.Context, error) {
	return p.issue(peer, customerID, profileID, claimID, activationV3Purpose)
}

// TakeCredentialV3 consumes once, even for a wrong-purpose attempt. It grants
// no access: verify possession against protected state and recheck live identity,
// expiry, revocation and authority at the actual delivery edge. No process-local
// challenge or its context is durable authority or a substitute for replay
// and reconciliation fences around persistent operations.
func (p *Pool) TakeCredentialV3(nonce string) (customerclaim.Context, error) {
	return p.take(nonce, credentialV3Purpose)
}

// TakeActivationV3 consumes once, including a wrong-purpose attempt. Before
// any activation, verify the exact certificate hash, original key and intent,
// and hold current v3 lifecycle/identity/authority guards through its edge.
func (p *Pool) TakeActivationV3(nonce string) (customerclaim.Context, error) {
	return p.take(nonce, activationV3Purpose)
}
