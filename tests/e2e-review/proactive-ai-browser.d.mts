/** Narrow read-only fixture exports used by the browser/DTO contract test. */
export const proactiveAIFixtureDevice: string;
export const proactiveAIFixtureHostname: string;
export const proactiveAIFixtureAddresses: string[];
export function proactiveAIIdentityFixture(status?: 'fresh' | 'stale' | 'not_collected'): unknown;
export function proactiveAIResultFixture(): unknown;
