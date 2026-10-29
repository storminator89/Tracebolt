# Customer Windows v3 possession proof candidate

This source-only contract separates first credential retrieval from activation.
The retrieval proof covers the committed intent digest and original identity,
purpose, request ID and fresh challenge; it does not require the client to know
the certificate before receiving it. Activation covers the same fields and the
hash of the exact received certificate. Both use the original claim key. The
server must derive the intent and certificate from its own committed protected
state, independently verify the stored certificate, and establish their exact
durable binding. A signature check is not an authorization decision.

The client must receive an authenticated public projection containing the exact
intent digest and original manager/customer/profile/claim/key binding. The
present `SigningMessage` uses the full internal intent only as an isolated
contract fixture. Do not send the internal intent to a device: it contains
operator and review data. A source-only public projection, local binding check,
client transcript and fixed-leaf verifier exist; authenticated distribution and
their integration into protected device state are not implemented.

The source-only challenge pool provides distinct credential and activation
purposes sharing its existing bounds and quotas. A future owner must issue and
consume these challenges against protected committed state, bind the original
state, and enforce current authority, revocation, expiry and
lease checks at every final delivery or activation edge. This verifier neither
consumes challenges nor detects replay, provides no HTTP endpoint or durable
fence, and cannot prove a certificate belongs to a committed v3 identity. The
v3 leaf's bytes alone cannot distinguish an otherwise identical v2 leaf; an
authoritative v3 store must never adopt v2 identities or grants. Fixtures do not
establish native Windows behavior, an installer, a release or a host permission.
