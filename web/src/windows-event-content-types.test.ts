import goFixture from './windows-event-content-go-fixture.json';
import { describe, expect, it } from 'vitest';
import { eventContentAccepted, eventContentRecord, eventContentResult, eventContentView, eventContentSessionExpires } from './windows-event-content-fixture';
import { EVENT_CONTENT_RESULT_BYTES, encodedContentBytes, eventContentNanos, validEventContentResult, validEventContentView, validSelectedEvent } from './windows-event-content-types';
import { windowsDeviceId } from './windows-inventory-fixture';
import { windowsEventsFixture } from './windows-events-fixture';
const event = () => ({ ...windowsEventsFixture().channels[0].rows[0], channel: 'Application' as const, recordId: '9007199254740993', timestamp: '2026-10-06T10:30:00.1234567Z' });
const record = () => eventContentAccepted(eventContentRecord([event()]));
describe('strict Windows selected message contract', () => {
    it('accepts the real portable Go request/receipt/report DTO projection without narrowing IDs or timestamps', () => {
        const fixture = goFixture as unknown as { record: import('./windows-event-content-types').EventContentRecord; page: unknown };
        expect(validEventContentResult(fixture.page, fixture.record)).toBe(true);
        expect(fixture.record.description.identity.sequence).toBe('9007199254740993');
        expect(fixture.record.description.query.events[0].recordId).toBe('18446744073709551615');
        expect(fixture.record.description.query.events[0].timestamp).toContain('.1234567Z');
    });
    it('accepts browser-safe full-width IDs and original 100ns times without numeric conversion', () => {
        expect(validSelectedEvent(event())).toBe(true); expect(validSelectedEvent({ ...event(), recordId: '18446744073709551615' })).toBe(true);
        expect(eventContentNanos(event().timestamp) % 1000000n).toBe(456700n);
        expect(validEventContentView(eventContentView(), windowsDeviceId, eventContentSessionExpires)).toBe(true);
        expect(validEventContentResult(eventContentResult(record()), record())).toBe(true);
    });
    it.each([9007199254740993, '09007199254740993', '18446744073709551616', '0', '-1'])('rejects narrowed or noncanonical IDs %s', id => expect(validSelectedEvent({ ...event(), recordId: id })).toBe(false));
    it('rejects unknown schema, fields, replacement sessions, altered identities and rounded timestamps', () => {
        expect(validEventContentView({ ...eventContentView(), extra: 'private' }, windowsDeviceId, eventContentSessionExpires)).toBe(false);
        expect(validEventContentView(eventContentView(), windowsDeviceId, '2026-10-08T13:00:00Z')).toBe(false);
        for (const field of ['recordId', 'provider', 'channel', 'timestamp']) { const r = record(), result = eventContentResult(r); (result.report.events[0].event as unknown as Record<string, unknown>)[field] = field === 'timestamp' ? '2026-10-06T10:30:00.123Z' : 'changed'; expect(validEventContentResult(result, record())).toBe(false); }
        expect(validSelectedEvent({ ...event(), timestamp: '2026-10-06T10:30:00.123456789Z' })).toBe(false);
    });
    it('distinguishes successfully empty text, missing/denied/publisher states and partial/truncated outcomes', () => {
        const r = record(), empty = eventContentResult(r, ['']); expect(validEventContentResult(empty, r)).toBe(true);
        for (const reason of ['windows_event_content_record_not_found', 'windows_event_content_identity_mismatch', 'windows_event_content_publisher_unavailable', 'windows_event_content_access_denied']) { const missing = eventContentResult(r, ['']); missing.report.quality = 'unavailable'; missing.report.complete = false; Object.assign(missing.report.events[0], { quality: 'unavailable', complete: false, reason }); expect(validEventContentResult(missing, r)).toBe(true); missing.report.events[0].message = 'leak'; expect(validEventContentResult(missing, r)).toBe(false); }
        const bounded = eventContentResult(r, ['x'.repeat(16384)]); Object.assign(bounded.report, { quality: 'bounded', complete: false, truncated: true }); Object.assign(bounded.report.events[0], { quality: 'bounded', complete: false, truncated: true, reason: 'windows_event_content_message_limit' }); expect(validEventContentResult(bounded, r)).toBe(true); bounded.report.events[0].message = 'too short'; expect(validEventContentResult(bounded, r)).toBe(false);
    });
    it('accepts worst-case escaped 64 KiB aggregate, independently caps messages/rows and encoded result', () => {
        const events = Array.from({ length: 4 }, (_, i) => ({ ...event(), recordId: String(i + 1) })), r = eventContentAccepted(eventContentRecord(events)), result = eventContentResult(r, events.map(() => '<'.repeat(16384)));
        expect(encodedContentBytes(result)).toBeGreaterThan(256 * 1024); expect(encodedContentBytes(result)).toBeLessThan(EVENT_CONTENT_RESULT_BYTES); expect(validEventContentResult(result, r)).toBe(true);
        result.report.events[0].message += '<'; expect(validEventContentResult(result, r)).toBe(false);
        const many = eventContentAccepted(eventContentRecord(Array.from({ length: 5 }, (_, i) => ({ ...event(), recordId: String(i + 1) })))); expect(validEventContentResult(eventContentResult(many, Array(5).fill('x'.repeat(16384))), many)).toBe(false);
        const invalid = eventContentResult(record()); invalid.report.events[0].message = '\ud800'; expect(validEventContentResult(invalid, record())).toBe(false);
    });
    it('rejects forged extended expiry, receipt or inconsistent aggregate state', () => {
        const r = record(), view = { ...eventContentView(), request: r, expectedFloor: '1', contentStatus: 'available' as const }; expect(validEventContentView(view, windowsDeviceId, eventContentSessionExpires)).toBe(true);
        r.description.expiresAt = '2026-10-07T12:30:10Z'; expect(validEventContentView(view, windowsDeviceId, eventContentSessionExpires)).toBe(false);
        const result = eventContentResult(record()); result.receipt = { ...result.receipt, resultDigest: 'sha256:' + 'a'.repeat(64) }; expect(validEventContentResult(result, record())).toBe(false);
        const inconsistent = eventContentResult(record()); inconsistent.report.complete = false; expect(validEventContentResult(inconsistent, record())).toBe(false);
    });
});
