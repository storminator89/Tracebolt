// Reviewed against the published preview.3 release and its exact asset digests.
// Never discover pins from manager responses, browser storage or a moving branch.
export const WINDOWS_SETUP_RELEASE = Object.freeze({
    version: 'v0.1.0-windows-preview.3',
    sourceCommit: '992b8d8c9d9693a97bd63301a3c147e1b2681357',
    name: 'Tracebolt-v0.0.0-setup-candidate-windows-amd64-Setup.exe',
    size: 25116672,
    sha256: '97fc385e513363e50e1a4adc56bda55f0b5e6c5270c2c794dd2a8b8ca8f87f5e',
});
const repository = 'https://github.com/storminator89/Tracebolt';
const download = `${repository}/releases/download/${WINDOWS_SETUP_RELEASE.version}`;
export const WINDOWS_SETUP_LINKS = Object.freeze({
    setup: `${download}/${WINDOWS_SETUP_RELEASE.name}`,
    guide: `${download}/windows-prerelease-install.md`,
    manifest: `${download}/release-manifest.json`,
    release: `${repository}/releases/tag/${WINDOWS_SETUP_RELEASE.version}`,
    source: `${repository}/tree/${WINDOWS_SETUP_RELEASE.sourceCommit}`,
});

export type WindowsSetupFileResult = 'matched' | 'different-file' | 'unavailable' | 'failed';

/** Public executable bytes stay in local memory. No upload, execution, trust
 * change, manager request or persistent result. A hash match is byte identity,
 * not publisher trust, native acceptance or permission to install. */
export async function checkWindowsSetupFile(file: Pick<File, 'name' | 'size' | 'arrayBuffer'>): Promise<WindowsSetupFileResult> {
    if (file.name !== WINDOWS_SETUP_RELEASE.name || file.size !== WINDOWS_SETUP_RELEASE.size) return 'different-file';
    if (!globalThis.crypto?.subtle || typeof file.arrayBuffer !== 'function') return 'unavailable';
    try {
        const bytes = await file.arrayBuffer();
        if (bytes.byteLength !== WINDOWS_SETUP_RELEASE.size) return 'different-file';
        const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
        const actual = Array.from(digest, value => value.toString(16).padStart(2, '0')).join('');
        return actual === WINDOWS_SETUP_RELEASE.sha256 ? 'matched' : 'different-file';
    } catch {
        return 'failed';
    }
}
