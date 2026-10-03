import { describe, expect, it } from 'vitest';
import { publicBootstrap } from './enrollment-types';
import type { EnrollmentBootstrap, EnrollmentSnapshot } from './enrollment-types';

// This is certificate framing data for UI contract tests, not a trusted X.509
// certificate. The native client, not the UI, performs cryptographic validation.
const certificate = '-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n';
const invitation = `invite_${'1'.repeat(32)}`;
function fixture() {
  const item = {
    invitationID: invitation,
    binding: { instanceID: `manager_${'2'.repeat(32)}`, origin: window.location.origin,
      profile: 'tls', collectionProfile: 'basic-readonly-v1', issuerFingerprint: 'a'.repeat(64) },
  } as EnrollmentSnapshot;
  const bootstrap: EnrollmentBootstrap = {
    schemaVersion: 'tracebolt.enrollment-bootstrap.v2', managerInstanceId: item.binding.instanceID,
    profile: 'tls', enrollmentOrigin: window.location.origin, agentOrigin: 'https://localhost:9443',
    collectionProfile: item.binding.collectionProfile, invitationId: invitation,
    serverCaPem: certificate, issuerRootPem: certificate, issuerPem: certificate,
  };
  return { item, bootstrap };
}

describe('independent enrollment public-export boundary', () => {
  it('returns only the fixed public schema as a detached object', () => {
    const { item, bootstrap } = fixture();
    const exported = publicBootstrap(bootstrap, item, 'synthetic-secret');
    expect(exported).toEqual(bootstrap);
    expect(exported).not.toBe(bootstrap);
    expect(publicBootstrap({ ...bootstrap, invitationSecret: 'synthetic-secret' }, item, 'synthetic-secret')).toBeNull();
  });

  it('rejects arbitrary or malformed prefixes in every certificate field', () => {
    const { item, bootstrap } = fixture();
    for (const field of ['serverCaPem', 'issuerRootPem', 'issuerPem'] as const) {
      for (const value of ['synthetic-unvalidated-prefix\n' + certificate,
        '-----BEGIN PRIVATE KEY-----\nmalformed\n' + certificate,
        'unstructured public-looking text']) {
        expect(publicBootstrap({ ...bootstrap, [field]: value }, item, 'synthetic-secret')).toBeNull();
      }
    }
  });

  it('rejects normalized aliases and invalid origins instead of downloading them', () => {
    const { item, bootstrap } = fixture();
    for (const origin of ['https://localhost:9443/', 'https://localhost:443', 'https://LOCALHOST:9443',
      ' https://localhost:9443', 'https://localhost:0', 'https://user@localhost:9443', 'https://localhost:9443?']) {
      expect(publicBootstrap({ ...bootstrap, agentOrigin: origin }, item, 'synthetic-secret')).toBeNull();
    }
  });

  it('rejects cross-manager binding and private material independently of field names', () => {
    const { item, bootstrap } = fixture();
    expect(publicBootstrap({ ...bootstrap, enrollmentOrigin: 'https://other.example' }, item, 'synthetic-secret')).toBeNull();
    expect(publicBootstrap({ ...bootstrap, managerInstanceId: `manager_${'3'.repeat(32)}` }, item, 'synthetic-secret')).toBeNull();
    expect(publicBootstrap({ ...bootstrap, issuerPem: '-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----\n' }, item, 'synthetic-secret')).toBeNull();
  });

  it('never exports the known invitation secret even in an otherwise public field', () => {
    const { item, bootstrap } = fixture();
    const secret = 'S'.repeat(43);
    const changed = { ...item, binding: { ...item.binding, collectionProfile: secret } };
    expect(publicBootstrap({ ...bootstrap, collectionProfile: secret }, changed, secret)).toBeNull();
  });
});
