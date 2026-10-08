import { sha256Bytes } from './sha256';

// Preserve the existing canonical ASCII affected-services projection and prefix.
export function affectedServicesDigest(services: readonly string[]): string {
    return `sha256:${sha256Bytes(new TextEncoder().encode(JSON.stringify({ version: 'tracebolt.service-action-affected-services.v2', services })))}`;
}
