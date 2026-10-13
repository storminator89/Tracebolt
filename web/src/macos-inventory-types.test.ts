import { describe, expect, it } from 'vitest';
import { macInventoryDeviceId, macInventoryFixture, macInventoryQuery, macInventoryLookupQuery } from './macos-inventory-fixture';
import { macInventorySections, macInventoryVisible, validMacInventoryPage, validMacInterface, validMacProcess, validMacDeviceId, validMacGenerationId, normalizeMacInventorySearch, validMacInventorySearch, macProcessMatches } from './macos-inventory-types';
import type { MacInventoryPage } from './macos-inventory-types';
const valid = (v: MacInventoryPage) => validMacInventoryPage(v, macInventoryDeviceId, macInventoryQuery(v.section));
describe('exact private Mac inventory pages', () => {
 it.each(['summary', ...macInventorySections] as const)('accepts bounded %s while rejecting cross-section and extra fields', section => {
  const v = macInventoryFixture(macInventoryQuery(section)); expect(valid(v)).toBe(true); expect(valid({ ...v, secret: 'extra' } as unknown as MacInventoryPage)).toBe(false); expect(validMacInventoryPage(v, `agent_${'8'.repeat(32)}`, macInventoryQuery(section))).toBe(false);
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


describe('strict generation-pinned lookup contract', () => {
 it.each(['receipts', 'processes'] as const)('keeps v1 %s exact and accepts only the v2 search echo', section => {
  const oldQuery = macInventoryQuery(section), query = macInventoryLookupQuery(section, 'fixture');
  const oldPage = macInventoryFixture(oldQuery), page = macInventoryFixture(query);
  expect(validMacInventoryPage(oldPage, macInventoryDeviceId, oldQuery)).toBe(true);
  expect(validMacInventoryPage(page, macInventoryDeviceId, query)).toBe(true);
  expect(validMacInventoryPage(oldPage, macInventoryDeviceId, query)).toBe(false);
  expect(validMacInventoryPage(page, macInventoryDeviceId, oldQuery)).toBe(false);
  for (const change of [{ search: 'other' }, { search: 'x'.repeat(257) }, { matchingCount: 4097 }, { matchingCount: -1 }, { matchingCount: -0 }, { matchingCount: 0 }, { extra: true }]) expect(validMacInventoryPage({ ...page, ...change }, macInventoryDeviceId, query)).toBe(false);
 });
 it.each(['Upper', ' leading', 'trailing ', '\t', '\n', '\x7f', 'ä', 'x'.repeat(257)])('rejects noncanonical search %j', search => {
  const query = macInventoryLookupQuery('receipts', search);
  expect(validMacInventorySearch(search)).toBe(false);
  expect(validMacInventoryPage(macInventoryFixture(query), macInventoryDeviceId, query)).toBe(false);
 });
 it('normalizes only ASCII outer spaces and case, with bounded literal content', () => {
  expect(normalizeMacInventorySearch('  FIXTURE + (42).*  ')).toBe('fixture + (42).*');
  expect(normalizeMacInventorySearch('   ')).toBe('');
  expect(normalizeMacInventorySearch('x'.repeat(256))).toHaveLength(256);
  for (const search of ['Ä', 'K', '\tquery', 'query\n', 'x'.repeat(257)]) expect(normalizeMacInventorySearch(search)).toBeNull();
 });
 it('supports observed zero matches with a nonzero source total and refuses unknown-source counts', () => {
  for (const section of ['receipts', 'processes'] as const) {
   const query = macInventoryLookupQuery(section, 'no-match'), page = macInventoryFixture(query);
   expect(validMacInventoryPage(page, macInventoryDeviceId, query)).toBe(true);
   expect(page.total).toBeGreaterThan(0);
   const sources = { ...page.sources!, [section]: { ...page.sources![section], quality: 'denied', reason: 'macos_inventory_access_denied' } };
   expect(validMacInventoryPage({ ...page, sources, sourceQuality: 'partial' }, macInventoryDeviceId, query)).toBe(false);
   expect(validMacInventoryPage({ ...page, sources, sourceQuality: 'partial', total: 0 }, macInventoryDeviceId, query)).toBe(true);
  }
 });
 it('validates filtered offsets against matchingCount, never total', () => {
  const query = { ...macInventoryLookupQuery('receipts', 'fixture', 50), limit: 50 };
  const page = { ...macInventoryFixture(query), total: 100, matchingCount: 51, receiptIds: ['com.fixture.tail'], nextOffset: null };
  expect(validMacInventoryPage(page, macInventoryDeviceId, query)).toBe(true);
  expect(validMacInventoryPage({ ...page, nextOffset: 51 }, macInventoryDeviceId, query)).toBe(false);
  expect(validMacInventoryPage({ ...page, matchingCount: 50 }, macInventoryDeviceId, query)).toBe(false);
  expect(validMacInventoryPage({ ...page, receiptIds: ['com.unrelated.tail'] }, macInventoryDeviceId, query)).toBe(false);
 });
 it('matches process fields separately without inventing missing labels or cross-field strings', () => {
  const row = { pid: 42, parentPid: 1, accountingName: 'Fixture-agent', nameQuality: 'observed' as const };
  expect(macProcessMatches(row, 'fixture')).toBe(true); expect(macProcessMatches(row, '42')).toBe(true); expect(macProcessMatches(row, '1')).toBe(true);
  for (const search of ['421', '42 1', 'agent42', '.*']) expect(macProcessMatches(row, search)).toBe(false);
  expect(macProcessMatches({ ...row, accountingName: '', nameQuality: 'unavailable' }, 'fixture')).toBe(false);
  const query = macInventoryLookupQuery('processes', '42'), page = macInventoryFixture(query);
  expect(validMacInventoryPage(page, macInventoryDeviceId, query)).toBe(true);
  expect(validMacInventoryPage({ ...page, processes: [{ ...row, pid: 43 }] }, macInventoryDeviceId, query)).toBe(false);
 });
 it('rejects v2 on other sections, unknown request fields and empty-search count contradictions', () => {
  const query = macInventoryLookupQuery(), page = macInventoryFixture(query);
  expect(validMacInventoryPage({ ...page, matchingCount: 2, receiptIds: page.receiptIds.slice(0, 2) }, macInventoryDeviceId, query)).toBe(false);
  expect(validMacInventoryPage(page, macInventoryDeviceId, { ...query, section: 'ipv4' } as unknown as typeof query)).toBe(false);
  expect(validMacInventoryPage(page, macInventoryDeviceId, { ...query, extra: true } as typeof query)).toBe(false);
  expect(validMacInventoryPage(page, macInventoryDeviceId, { ...query, generationId: '' })).toBe(false);
 });
});
