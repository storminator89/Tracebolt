/** Exact PR-only subset. Its result can never be full browser/native evidence. */
export const smokeNames = Object.freeze([
  'Real HTTP-test login defaults to English, blocks protected data and retains a localized transport warning',
  'Malformed or unavailable bootstrap fails closed and explicit retry recovers without fake access',
  'Actual password rejection and repeated login clear the draft, use one request and keep session cookies out of script storage',
  'Real CSRF-protected logout removes private content and rejects later protected API reads',
  'Actual short session expiry locks the browser and backend using server-relative TTL',
  'Unconfirmed logout stays locked across reload and explicit retry performs real logout',
]);
export function smokeMode(args) {
  if (args.length === 0) return false;
  if (args.length === 1 && args[0] === '--pr-smoke') return true;
  throw new Error('Unknown browser selection; no checks executed.');
}
export function requireSmoke(results) {
  if (results.length !== smokeNames.length || new Set(results.map(row => row.name)).size !== smokeNames.length ||
      results.some(row => !smokeNames.includes(row.name) || row.status !== 'PASS')) {
    throw new Error('Missing, duplicate, skipped, failed or unexpected PR browser smoke case.');
  }
}
