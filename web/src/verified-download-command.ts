import { preparedEnrollmentCommand, publicEnrollmentArguments } from './enrollment-command';
import { publicBootstrap } from './enrollment-types';
import type { EnrollmentCollectionProfile, EnrollmentSnapshot } from './enrollment-types';

type BootstrapPublicationPin = Readonly<{ version: string; publicationCommit: string; bootstrapSHA256: string }>;

// Activation is a reviewed source change after official publication and readback.
// This is the bootstrap publication commit, NOT the binary/source build commit.
// Never populate it from API data, manager configuration, environment or storage.
export const OFFICIAL_LINUX_BOOTSTRAP_PIN: BootstrapPublicationPin | null = { version: 'v0.1.0-rc.2', publicationCommit: '08c7f0ef3bb8c3f8941a071d885bdf550c7f72c5', bootstrapSHA256: '10b372ed31d0b2e04d901286ed477a9e7b4fc4d1efe7faea78a5ae8a284db4ea' };

const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
function validPin(value: unknown): value is BootstrapPublicationPin {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const pin = value as Record<string, unknown>;
    return Object.keys(pin).length === 3 && ['version', 'publicationCommit', 'bootstrapSHA256'].every(key => Object.hasOwn(pin, key)) &&
        typeof pin.version === 'string' && pin.version.length <= 64 && pin.version.trim() === pin.version && /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?$/.test(pin.version) &&
        typeof pin.publicationCommit === 'string' && pin.publicationCommit.length === 40 && /^[0-9a-f]{40}$/.test(pin.publicationCommit) &&
        typeof pin.bootstrapSHA256 === 'string' && pin.bootstrapSHA256.length === 64 && /^[0-9a-f]{64}$/.test(pin.bootstrapSHA256);
}

// Only this explicitly reviewed release supports the combined read-admin v2 flow.
// Future releases require a source review, rather than an inferred version range.
const READ_ADMIN_RELEASE_VERSION = 'v0.1.0-rc.2';
export function verifiedLinuxDownloadAvailable(profile: EnrollmentCollectionProfile = 'basic-readonly-v1'): boolean {
    return validPin(OFFICIAL_LINUX_BOOTSTRAP_PIN) &&
        (profile !== 'managed-operations-v3' || OFFICIAL_LINUX_BOOTSTRAP_PIN.version === READ_ADMIN_RELEASE_VERSION);
}

/** Inert serializer. The explicit pin parameter is for source review/fixtures;
 * the invitation UI calls only selectEnrollmentCommand, which has no pin input.
 * No networking, child execution, secret input or trust discovery happens here. */
export function verifiedDownloadCommand(pin: unknown, value: unknown, snapshot: EnrollmentSnapshot, checksum: unknown): string | null {
    if (!validPin(pin)) return null;
    const publicArguments = publicEnrollmentArguments(value, snapshot, checksum);
    if (publicArguments === null) return null;
    const bootstrap = publicBootstrap(value, snapshot, '');
    if (!bootstrap) return null;
    const complete = bootstrap.collectionProfile === 'managed-operations-v3';
    if (complete && pin.version !== READ_ADMIN_RELEASE_VERSION) return null;
    const installMode = complete
        ? ` --read-admin --read-admin-agent-origin ${shellQuote(bootstrap.agentOrigin)}`
        : ' --pending-service';
    const url = `https://raw.githubusercontent.com/storminator89/Tracebolt/${pin.publicationCommit}/deploy/release/published/${pin.version}.py`;
    // The inner shell is foreground with inherited terminal stdin. Only the hash
    // check uses a pipe; downloaded bytes never become shell input. Open the verified
    // bytes on fd 3, remove staging, then replace the shell so cancellation is owned
    // by the reviewed bootstrap. No wrapper timeout or background installer.
    // Keep clipboard text on one physical line; validated public PEM is base64.
    const script = [
        'set -eu',
        'umask 077',
        '[ "$(id -u)" -eq 0 ] || { printf "%s\\n" "Run deliberately as root after approving account, service and persistent identity creation. No automatic elevation." >&2; exit 1; }',
        '[ -t 0 ] || { printf "%s\\n" "A real local terminal is required for hidden invitation entry." >&2; exit 1; }',
        'missing=""',
        'for tool in curl sha256sum python3 mktemp rm rmdir; do command -v "$tool" >/dev/null || missing="$missing $tool"; done',
        '[ -z "$missing" ] || { printf "%s\\n" "Missing prerequisites:$missing. No tools were installed." "On supported Debian 13 or Ubuntu 24.04, after administrator approval, run manually as root:" "apt-get update && apt-get install -- curl python3 ca-certificates coreutils" "Then retry the same reviewed installation command." >&2; exit 1; }',
        'stage=$(mktemp -d /tmp/tracebolt-bootstrap.XXXXXXXXXX)',
        'trap \'status=$?; trap - 0; rm -f -- "$stage/bootstrap.py"; rmdir -- "$stage"; exit "$status"\' 0',
        'trap \'exit 129\' HUP',
        'trap \'exit 130\' INT',
        'trap \'exit 143\' TERM',
        `status=$(curl -q --fail --silent --show-error --proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' --max-redirs 0 --connect-timeout 10 --max-time 60 --max-filesize 131072 --output "$stage/bootstrap.py" --write-out '%{http_code}' ${shellQuote(url)})`,
        '[ "$status" = 200 ] || { printf "%s\\n" "Official bootstrap download did not return HTTP 200." >&2; exit 1; }',
        `printf '%s  %s\\n' ${shellQuote(pin.bootstrapSHA256)} "$stage/bootstrap.py" | sha256sum --check --status || { printf "%s\\n" "Official bootstrap SHA-256 mismatch. Nothing was executed." >&2; exit 1; }`,
        'exec 3< "$stage/bootstrap.py"',
        'rm -f -- "$stage/bootstrap.py"',
        'rmdir -- "$stage"',
        'trap - 0 HUP INT TERM',
        `exec python3 -I -B /proc/self/fd/3 --action install --apply${installMode}${publicArguments}`,
    ].join('; ');
    // A clean environment also excludes ambient curl CA/proxy configuration and
    // Python startup variables. curl -q must remain its first option.
    return '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 /bin/sh -c ' + shellQuote(script);
}

export type EnrollmentCommand = { kind: 'prepared-local'; command: string } | { kind: 'verified-download'; command: string };
/** The production UI has no release-pin parameter or manager-controlled switch. */
export function selectEnrollmentCommand(value: unknown, snapshot: EnrollmentSnapshot, checksum: unknown): EnrollmentCommand | null {
    const downloaded = verifiedDownloadCommand(OFFICIAL_LINUX_BOOTSTRAP_PIN, value, snapshot, checksum);
    if (downloaded !== null) return { kind: 'verified-download', command: downloaded };
    // The manual serializer also rejects complete profiles: no base-only fallback.
    const prepared = preparedEnrollmentCommand(value, snapshot, checksum);
    return prepared === null ? null : { kind: 'prepared-local', command: prepared };
}
