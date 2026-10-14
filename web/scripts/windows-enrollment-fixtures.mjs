/** Inert DTOs only. These values cannot enroll a device or authenticate a session. */
export const now = '2026-10-14T09:00:00Z';
export const invitation = `invite_${'1'.repeat(32)}`;
export const secret = 'SYNTHETIC_ONLY_NOT_AN_INVITATION_1234567890';
export const csrf = 'synthetic-csrf-not-a-session';
export function record(origin) {
 const seconds = Date.parse(now) / 1000, fingerprint = 'ab'.repeat(32);
 return {
  version: 'tracebolt.enrollment-state.v2', binding: { instanceID: `manager_${'2'.repeat(32)}`, origin, profile: 'tls', collectionProfile: 'windows-inventory-v1', issuerFingerprint: 'a'.repeat(64) },
  invitationID: invitation, createRequestID: `request_${'3'.repeat(32)}`, platform: 'windows', revision: 1, state: 'created', createdAt: seconds, deadlineAt: seconds + 600, updatedAt: seconds,
  claim: { claimID: `claim_${'4'.repeat(32)}`, requestID: '', keyFingerprint: fingerprint, csrHash: '', claimHash: '', comparisonCode: '12ab'.repeat(8), at: seconds },
  approval: { requestID: '', deviceID: '', keyFingerprint: fingerprint, at: seconds },
  intent: { intentID: '', requestID: '', serialHex: '', templateVersion: '', deviceID: '', keyFingerprint: '', notBefore: 0, notAfter: 0, at: 0 },
  issuance: { requestID: '', certificateHash: '', at: 0 }, activation: { requestID: '', at: 0 }, termination: { requestID: '', from: '', at: 0 },
 };
}
export function listing(items = []) {
 return { schemaVersion: 'tracebolt.enrollment-operator.v2', serverNow: now, enabled: true, platforms: ['windows'], recordLimit: 25, collectionProfile: 'windows-inventory-v1', collectionPrivacy: 'windows_inventory_metadata_may_be_sensitive', items };
}
export function creation(origin) {
 const snapshot = record(origin), certificate = '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
 return { schemaVersion: 'tracebolt.enrollment-invitation.v2', serverNow: now, snapshot, invitationSecret: secret, bootstrapSHA256: 'b'.repeat(64), bootstrap: { schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: snapshot.binding.instanceID, profile: 'tls', enrollmentOrigin: origin, agentOrigin: 'https://synthetic-agent.invalid:9443', collectionProfile: 'windows-inventory-v1', invitationId: invitation, serverCaPem: certificate, issuerRootPem: certificate, issuerPem: certificate } };
}
export function approvedBody(requestId) {
 return JSON.stringify({ requestId, platform: 'windows', collectionAcknowledged: true, insecureHTTPAcknowledged: false });
}
