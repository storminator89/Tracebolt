import { describe, expect, it } from 'vitest';
import { macInventoryDeviceId, macInventoryFixture, macInventoryQuery } from './macos-inventory-fixture';
import { macInventorySections, macInventoryVisible, validMacInventoryPage, validMacInterface, validMacProcess, validMacDeviceId, validMacGenerationId } from './macos-inventory-types';
import type { MacInventoryPage } from './macos-inventory-types';
const valid = (v: MacInventoryPage) => validMacInventoryPage(v, macInventoryDeviceId, macInventoryQuery(v.section));
describe('exact private Mac inventory pages', () => {
 it.each(['summary', ...macInventorySections] as const)('accepts bounded %s while rejecting cross-section and extra fields', section => {
  const v = macInventoryFixture(macInventoryQuery(section)); expect(valid(v)).toBe(true); expect(valid({ ...v, secret: 'extra' } as MacInventoryPage)).toBe(false); expect(validMacInventoryPage(v, `agent_${'8'.repeat(32)}`, macInventoryQuery(section))).toBe(false);
 });
 it.each(['authorityUntil', 'generationId', 'expiresAt', 'sourceQuality', 'sources', 'total', 'nextOffset'] as const)('rejects contradictory %s', field => {
  const v = macInventoryFixture(macInventoryQuery('receipts'));
  const mutations = { authorityUntil: v.serverNow, generationId: `sample_${'b'.repeat(32)}`, expiresAt: '2026-10-14T10:01:00Z', sourceQuality: 'unknown', sources: null, total: 2, nextOffset: 0 };
  expect(valid({ ...v, [field]: mutations[field] })).toBe(false);
 });
 it('keeps unknown failed sources distinct from observed empty receipts', () => {
  const page = macInventoryFixture(macInventoryQuery('receipts')); page.receiptIds = []; page.total = 0;
  expect(valid(page)).toBe(true);
  page.sources!.receipts = { ...page.sources!.receipts, quality: 'denied', reason: 'macos_inventory_access_denied' }; page.sourceQuality = 'partial';
  expect(valid(page)).toBe(true); page.receiptIds = ['com.example.leak']; page.total = 1; expect(valid(page)).toBe(false);
 });
 it('accepts expired summary without treating quality as freshness and disallows expired rows', () => {
  const v = macInventoryFixture(); v.status = 'expired'; v.serverNow = v.expiresAt!; v.authorityUntil = '2026-10-14T11:00:00Z'; expect(valid(v)).toBe(true);
  v.section = 'receipts'; expect(valid(v)).toBe(false);
 });
 it('rejects unexpected process arguments, owners, path-like or long labels and unsafe PIDs', () => {
  const row = macInventoryFixture(macInventoryQuery('processes')).processes[0];
  expect(validMacProcess({ ...row, owner: 'somebody' })).toBe(false); expect(validMacProcess({ ...row, accountingName: '/bin/program' })).toBe(false); expect(validMacProcess({ ...row, accountingName: 'x'.repeat(17) })).toBe(false); expect(validMacProcess({ ...row, pid: 2147483648 })).toBe(false);
  expect(validMacProcess({ ...row, accountingName: '', nameQuality: 'unavailable' })).toBe(true);
 });
 it('rejects hostnames, zones, family confusion, mapped IPv6 and duplicate addresses', () => {
  const row = macInventoryFixture(macInventoryQuery('ipv6')).interfaces[0];
  for (const ip of ['host.example', 'fe80::1%en0', '192.0.2.1', '::ffff:192.0.2.1']) expect(validMacInterface({ ...row, addresses: [{ ip, prefixBits: 24 }] }, 'ipv6')).toBe(false);
  expect(validMacInterface({ ...row, addresses: [row.addresses[0], row.addresses[0]] }, 'ipv6')).toBe(false);
 });
 it('expires at the earliest original authority deadline and never accepts a clock reversal', () => {
  const v = macInventoryFixture(); v.authorityUntil = '2026-10-13T10:00:11Z'; expect(macInventoryVisible(v, 999)).toBe(true); expect(macInventoryVisible(v, 1000)).toBe(false); expect(macInventoryVisible(v, -1)).toBe(false); expect(macInventoryVisible(v, Infinity)).toBe(false);
 });
});

it('rejects all-zero identity/generation suffixes and malformed paging requests', () => {
 expect(validMacDeviceId(`agent_${'0'.repeat(32)}`)).toBe(false); expect(validMacGenerationId(`sample_${'0'.repeat(32)}`)).toBe(false);
 const page=macInventoryFixture(); expect(validMacInventoryPage(page,macInventoryDeviceId,{...macInventoryQuery(),limit:0})).toBe(false); expect(validMacInventoryPage(page,macInventoryDeviceId,{...macInventoryQuery(),limit:101})).toBe(false);
 const network=macInventoryFixture(macInventoryQuery('ipv4')).interfaces[0]; expect(validMacInterface({...network,addresses:[{ip:'192.0.2.2',prefixBits:24},{ip:'192.0.2.1',prefixBits:24}]},'ipv4')).toBe(false);
});
