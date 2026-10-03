import { describe, expect, it } from 'vitest';
import { csvCell, decodeRouteId, defaultFilters, filterDevices, fullDate, noteBytes, relativeTime, normalizeFilters } from './utils';
import type { Device } from './types';
const device = (id: string, status: Device['status'], platform: Device['platform'] = 'linux'): Device => ({id,name:id,status,platform,os:platform,site:'Berlin',group:'Test',ip:null,source:'synthetic',synthetic:true,tags:['Demo'],lastSeen:'2026-10-03T12:00:00Z'} as Device);
describe('inventory filtering', () => {
  const devices=[device('healthy','healthy'),device('warn','attention','windows'),device('critical','critical'),device('stale','stale'),device('unknown','unknown')];
  it('prioritizes critical, warnings, stale, unknown, then observed healthy',()=>expect(filterDevices(devices,defaultFilters).map(d=>d.id)).toEqual(['critical','warn','stale','unknown','healthy']));
  it('aggregates attention tile without dropping critical devices',()=>expect(filterDevices(devices,{...defaultFilters,status:'needs-attention'}).map(d=>d.id)).toEqual(['critical','warn']));
  it('combines platform, status and case-insensitive search',()=>expect(filterDevices(devices,{...defaultFilters,platform:'windows',query:'BERLIN',status:'attention'})).toHaveLength(1));
  it('returns an empty state for unknown terms',()=>expect(filterDevices(devices,{...defaultFilters,query:'missing'})).toEqual([]));
  it('separates synthetic from sandbox sources',()=>expect(filterDevices([...devices,{...device('sandbox','unknown'),source:'sandbox',synthetic:false}],{...defaultFilters,source:'synthetic'})).toHaveLength(5));
});
describe('safe exports and routes',()=>{
  it.each(['=HYPERLINK("https://example.test")','+CMD','-CMD','@SUM(1)','\t=CMD','\r=CMD','  =CMD'])('neutralizes spreadsheet formula %s',value=>expect(csvCell(value).startsWith('"\'')).toBe(true));
  it('escapes CSV quotes',()=>expect(csvCell('normal "name"')).toBe('"normal ""name"""'));
  it('keeps numeric values intact',()=>expect(csvCell(92)).toBe('"92"'));
  it('handles malformed fragments safely',()=>expect(decodeRouteId('%E0%A4%A')).toBeUndefined());
  it('decodes valid IDs',()=>expect(decodeRouteId('demo%20linux')).toBe('demo linux'));
  it('counts UTF-8 bytes instead of characters',()=>{expect(noteBytes('hello')).toBe(5);expect(noteBytes('ü')).toBe(2);expect(noteBytes('🚀')).toBe(4);});
  it('does not pretend malformed times are current',()=>{expect(relativeTime('bad')).toBe('Zeitpunkt unbekannt');expect(fullDate('bad')).toBe('Zeitpunkt unbekannt');});
});

describe("stored state validation",()=>{it("normalizes malformed filters instead of crashing",()=>expect(normalizeFilters({query:null,platform:"invalid",status:42,sort:{},source:null})).toEqual(defaultFilters));it("preserves valid filters",()=>expect(normalizeFilters({...defaultFilters,query:"Berlin",platform:"windows"})).toEqual({...defaultFilters,query:"Berlin",platform:"windows"}));});

describe("awaiting telemetry time",()=>{it("treats Go zero time as unknown instead of ancient observation",()=>{expect(relativeTime("0001-01-01T00:00:00Z")).toBe("Zeitpunkt unbekannt");expect(fullDate("0001-01-01T00:00:00Z")).toBe("Zeitpunkt unbekannt");});it("treats unset times as unknown",()=>{expect(relativeTime("")).toBe("Zeitpunkt unbekannt");expect(fullDate("")).toBe("Zeitpunkt unbekannt");});});

describe("local native source coverage",()=>{it("includes both native local and sandbox observations in the local-source view",()=>{const native={...device("native-mac","unknown","macos"),source:"local" as const,synthetic:false};const sandbox={...device("sandbox","unknown"),source:"sandbox" as const,synthetic:false};const demo=device("demo","healthy","windows");expect(filterDevices([demo,native,sandbox],{...defaultFilters,source:"local"}).map(d=>d.id)).toEqual(["native-mac","sandbox"]);expect(filterDevices([demo,native,sandbox],{...defaultFilters,source:"sandbox"}).map(d=>d.id)).toEqual(["sandbox"]);});});
