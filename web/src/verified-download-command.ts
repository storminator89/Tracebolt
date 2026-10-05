import { preparedEnrollmentCommand, publicEnrollmentArguments } from './enrollment-command';
import type { EnrollmentSnapshot } from './enrollment-types';

type BootstrapPublicationPin = Readonly<{ version: string; publicationCommit: string; bootstrapSHA256: string }>;

// Activation is a reviewed source change after official publication and readback.
// This is the bootstrap publication commit, NOT the binary/source build commit.
// Never populate it from API data, manager configuration, environment or storage.
export const OFFICIAL_LINUX_BOOTSTRAP_PIN: BootstrapPublicationPin | null = { version: 'v0.1.0-pilot.2', publicationCommit: '1011c6b8d38cf85d77a342addf0493cbe1f828ca', bootstrapSHA256: 'ba0cf2b8bb25868782bbf9f7a2ae228a982895dd45f865314c6620af30731457' };

const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
function validPin(value: unknown): value is BootstrapPublicationPin {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const pin = value as Record<string, unknown>;
    return Object.keys(pin).length === 3 && ['version', 'publicationCommit', 'bootstrapSHA256'].every(key => Object.hasOwn(pin, key)) &&
        typeof pin.version === 'string' && pin.version.length <= 64 && pin.version.trim() === pin.version && /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?$/.test(pin.version) &&
        typeof pin.publicationCommit === 'string' && pin.publicationCommit.length === 40 && /^[0-9a-f]{40}$/.test(pin.publicationCommit) &&
        typeof pin.bootstrapSHA256 === 'string' && pin.bootstrapSHA256.length === 64 && /^[0-9a-f]{64}$/.test(pin.bootstrapSHA256);
}

export function verifiedLinuxDownloadAvailable(): boolean { return validPin(OFFICIAL_LINUX_BOOTSTRAP_PIN); }

/** Inert serializer. The explicit pin parameter is for source review/fixtures;
 * the invitation UI calls only selectEnrollmentCommand, which has no pin input.
 * No networking, child execution, secret input or trust discovery happens here. */
export function verifiedDownloadCommand(pin: unknown, value: unknown, snapshot: EnrollmentSnapshot, checksum: unknown): string | null {
    if (!validPin(pin)) return null;
    const publicArguments = publicEnrollmentArguments(value, snapshot, checksum);
    if (publicArguments === null) return null;
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
        'for tool in curl sha256sum python3 mktemp rm rmdir; do command -v "$tool" >/dev/null || { printf "%s\\n" "Missing prerequisite: $tool. No tools were installed." >&2; exit 1; }; done',
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
        `exec python3 -I -B /proc/self/fd/3 --action install --apply --pending-service${publicArguments}`,
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
    const prepared = preparedEnrollmentCommand(value, snapshot, checksum);
    return prepared === null ? null : { kind: 'prepared-local', command: prepared };
}
