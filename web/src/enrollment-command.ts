import { publicBootstrap, validBootstrapSHA256, validSnapshot } from './enrollment-types';
import type { EnrollmentSnapshot } from './enrollment-types';

const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
/** Public configuration only. This serializer has no invitation-secret input and
 * never downloads or claims to authenticate local binaries. The operator must
 * run it as root from their independently prepared/reviewed source checkout. */
export function preparedEnrollmentCommand(value: unknown, snapshot: EnrollmentSnapshot, checksum: unknown): string | null {
    if (!validSnapshot(snapshot) || snapshot.state !== 'created' || !validBootstrapSHA256(checksum) || typeof checksum !== 'string') return null;
    const bootstrap = publicBootstrap(value, snapshot, '');
    if (!bootstrap) return null;
    let command = '"$PWD/bin/agent-service" --action install --apply --pending-service' +
        ' --agent-binary "$PWD/bin/lan-agent" --agent-sha256 "$(sha256sum < "$PWD/bin/lan-agent" | cut -d \' \' -f 1)"' +
        ' --enroll-binary "$PWD/bin/enroll-agent" --enroll-sha256 "$(sha256sum < "$PWD/bin/enroll-agent" | cut -d \' \' -f 1)"' +
        ' --source-archive "$PWD/tracebolt-selected-source.tar" --source-sha256 "$(sha256sum < "$PWD/tracebolt-selected-source.tar" | cut -d \' \' -f 1)"' +
        ` --manager-origin ${shellQuote(bootstrap.enrollmentOrigin)} --invitation-id ${shellQuote(bootstrap.invitationId)} --bootstrap-sha256 ${shellQuote(checksum)}`;
    if (bootstrap.profile === 'tls') {
        // Base64 is the exact UTF-8 public PEM, not an X.509/publisher verification.
        const encoded = btoa(Array.from(new TextEncoder().encode(bootstrap.serverCaPem), byte => String.fromCharCode(byte)).join(''));
        command += ` --server-ca-base64 ${shellQuote(encoded)}`;
    } else command += ' --insecure-http-test';
    return command;
}
