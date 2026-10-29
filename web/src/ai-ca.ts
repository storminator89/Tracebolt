// Computes a display fingerprint only. Backend validates the certificate's CA
// properties and trust policy independently; browser parsing establishes no trust.
export async function publicCAFingerprint(pem: string): Promise<string> {
    if (!pem || new TextEncoder().encode(pem).length > 4096 || !globalThis.crypto?.subtle) throw new Error('invalid public CA');
    const match = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END CERTIFICATE-----\r?\n?$/.exec(pem);
    if (!match) throw new Error('invalid public CA');
    const encoded = match[1].replace(/\r?\n/g, '');
    if (!encoded || /[^A-Za-z0-9+/=]/.test(encoded)) throw new Error('invalid public CA');
    const decoded = atob(encoded);
    if (!decoded || btoa(decoded) !== encoded) throw new Error('invalid public CA');
    const bytes = Uint8Array.from(decoded, char => char.charCodeAt(0));
    const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), n => n.toString(16).padStart(2, '0')).join('');
}
