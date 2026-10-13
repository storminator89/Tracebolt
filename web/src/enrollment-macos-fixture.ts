/** Synthetic public UI contract only. No endpoint, key, usable invitation or login. */
import type { EnrollmentList, EnrollmentSnapshot, EnrollmentState, InvitationCreation } from './enrollment-types';
export const macOSFixtureNow = '2026-10-13T10:00:00Z';
export const macOSFixtureInvitation = `invite_${'1'.repeat(32)}`;
export const macOSFixtureSecret = 'SYNTHETIC_ONLY_NOT_AN_INVITATION_1234567890';
export function macOSFixtureRecord(origin: string, state: EnrollmentState = 'created', revision = 1): EnrollmentSnapshot {
 const seconds=Date.parse(macOSFixtureNow)/1000, fingerprint='ab'.repeat(32);
 return {
  version:'tracebolt.enrollment-state.v2', binding:{instanceID:`manager_${'2'.repeat(32)}`, origin, profile:'tls',collectionProfile:'basic-readonly-v1',issuerFingerprint:'a'.repeat(64)},
  invitationID:macOSFixtureInvitation,createRequestID:`request_${'3'.repeat(32)}`,platform:'darwin',revision,state,createdAt:seconds,deadlineAt:seconds+600,updatedAt:seconds,
  claim:{claimID:`claim_${'4'.repeat(32)}`,requestID:'',keyFingerprint:fingerprint,csrHash:'',claimHash:'',comparisonCode:'12ab'.repeat(8),at:seconds},
  approval:{requestID:'',deviceID:['created','claimed_pending'].includes(state)?'':`agent_${'6'.repeat(32)}`,keyFingerprint:fingerprint,at:seconds},
  intent:{intentID:'',requestID:'',serialHex:'',templateVersion:'',deviceID:'',keyFingerprint:'',notBefore:0,notAfter:0,at:0},issuance:{requestID:'',certificateHash:'',at:0},activation:{requestID:'',at:0},termination:{requestID:'',from:'',at:0},
 };
}
export function macOSFixtureList(items: EnrollmentSnapshot[] = []): EnrollmentList {
 return {schemaVersion:'tracebolt.enrollment-operator.v2',serverNow:macOSFixtureNow,enabled:true,platforms:['darwin'],recordLimit:25,collectionProfile:'basic-readonly-v1',items};
}
export function macOSFixtureCreation(origin: string, renewable=false): InvitationCreation {
 const snapshot=macOSFixtureRecord(origin),certificate='-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----';
 return {schemaVersion:'tracebolt.enrollment-invitation.v2',serverNow:macOSFixtureNow,snapshot,invitationSecret:macOSFixtureSecret,bootstrapSHA256:'b'.repeat(64),bootstrap:{schemaVersion:renewable?'tracebolt.enrollment-bootstrap.renewable.v1':'tracebolt.enrollment-bootstrap.v2',...(renewable?{renewalPolicy:'same-key-v1' as const}:{}),managerInstanceId:snapshot.binding.instanceID,profile:'tls',enrollmentOrigin:origin,agentOrigin:'https://synthetic-agent.invalid:9443',collectionProfile:'basic-readonly-v1',invitationId:snapshot.invitationID,serverCaPem:certificate,issuerRootPem:certificate,issuerPem:certificate}};
}
