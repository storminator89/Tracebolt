// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { proactiveAIIdentityFixture, proactiveAIFixtureAddresses, proactiveAIFixtureDevice, proactiveAIFixtureHostname, proactiveAIResultFixture } from '../../tests/e2e-review/proactive-ai-browser.mjs';
import { fleetIdentityProjection, validFleetIdentityView } from './fleet-identity-types';

describe('hosted proactive selector metadata contract', () => {
    it.each(['fresh', 'stale', 'not_collected'] as const)('accepts the actual %s hosted DTO without changing source age or identity', status => {
        const value = proactiveAIIdentityFixture(status);
        expect(validFleetIdentityView(value)).toBe(true);
        if (!validFleetIdentityView(value)) throw new Error('Invalid hosted identity fixture');
        const displayed = fleetIdentityProjection(value, 0).get(proactiveAIFixtureDevice)!;
        expect(displayed.status).toBe(status);
        expect(value.items[0].deviceId).toBe(proactiveAIFixtureDevice);
        if (status === 'not_collected') {
            expect(displayed.hostname).toBeNull();
            expect(displayed.addresses).toEqual([]);
        } else {
            expect(displayed.hostname).toBe(proactiveAIFixtureHostname);
            expect(displayed.addresses.map(address => address.address)).toEqual(proactiveAIFixtureAddresses);
            expect(displayed.addresses.map(address => [address.interfaceName, address.scope])).toEqual([['eth0', 'private'], ['eth0', 'link-local']]);
            expect(displayed.collectedAt).toBe(value.items[0].latest!.collectedAt);
            expect(fleetIdentityProjection(value, 86400000).get(proactiveAIFixtureDevice)).toMatchObject({ status: 'expired', hostname: null, addresses: [] });
        }
        for (const text of [proactiveAIFixtureHostname, ...proactiveAIFixtureAddresses]) expect(JSON.stringify(proactiveAIResultFixture())).not.toContain(text);
    });
});
