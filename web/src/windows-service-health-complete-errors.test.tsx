import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { windowsCapacityDevice } from './windows-capacity-fixture';
import { completeHealthSession, completeHealthView } from './windows-service-health-complete-fixture';
import { WindowsServiceHealthCompletePanel } from './windows-service-health-complete';
import { windowsServiceHealthCompleteCopy } from './windows-service-health-complete-copy';
import type { WindowsServiceHealthCompleteFailure, WindowsServiceHealthCompleteResource } from './windows-service-health-complete-resource';
const failures: WindowsServiceHealthCompleteFailure[] = ['session', 'authority', 'clock', 'timeout', 'invalid', 'unavailable'];
const expected = {
 en: ['Your session has ended.', 'Current device access could not be verified.', 'The time reference changed.', 'The manager did not respond in time.', 'The policy response could not be verified.', 'The policy could not be read.'],
 de: ['Die Sitzung ist beendet.', 'Der aktuelle Gerätezugriff konnte nicht bestätigt werden.', 'Der Zeitbezug hat sich geändert.', 'Der Manager hat nicht rechtzeitig geantwortet.', 'Die Richtlinienantwort konnte nicht verifiziert werden.', 'Die Richtlinie konnte nicht gelesen werden.'],
};
function props(error: WindowsServiceHealthCompleteFailure | null) {
 const view = completeHealthView(), device = windowsCapacityDevice(); device.id = view.deviceId; device.agentCertificate!.checkedAt = view.serverNow; device.agentCertificate!.expiresAt = view.certificateExpiresAt;
 const resource: WindowsServiceHealthCompleteResource = { view, draftGeneration: 0, elapsedMS: 0, loading: false, saving: false, error, notice: null, unresolved: false, refresh: vi.fn(), save: vi.fn() };
 return { device, resource, sessionKey: completeHealthSession, metadataReady: true, admin: true };
}
beforeEach(() => { vi.stubGlobal('fetch', vi.fn()); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe.each(['en', 'de'] as const)('complete service failure guidance (%s)', locale => {
 it.each(failures)('explains %s without disclosing retained observations or issuing requests', error => {
  setLocale(locale, false); const p = props(error), c = windowsServiceHealthCompleteCopy[locale]; render(<WindowsServiceHealthCompletePanel {...p}/>);
  const notice = screen.getByText(text => text.startsWith(expected[locale][failures.indexOf(error)])); expect(notice).toHaveAttribute('role', 'status'); expect(notice).toBeVisible(); expect(screen.queryByText(c.unavailable)).toBeNull();
  expect(document.querySelector('.windows-capacity-assessment strong')).toHaveTextContent(c.unknown); expect(document.querySelector('.windows-service-checks')).toBeNull();
  expect(p.resource.refresh).not.toHaveBeenCalled(); expect(p.resource.save).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
  const refresh = screen.getByRole('button', { name: c.refresh });
  if (error === 'session') { expect(refresh).toBeDisabled(); fireEvent.click(refresh); expect(p.resource.refresh).not.toHaveBeenCalled(); }
  else { expect(refresh).toBeEnabled(); fireEvent.click(refresh); expect(p.resource.refresh).toHaveBeenCalledOnce(); }
  expect(p.resource.save).not.toHaveBeenCalled(); expect(fetch).not.toHaveBeenCalled();
 });
 it('preserves pending precedence and clears error text on recovery', () => {
  setLocale(locale, false); const p = props('timeout'), c = windowsServiceHealthCompleteCopy[locale]; const rendered = render(<WindowsServiceHealthCompletePanel {...p} resource={{ ...p.resource, loading: true }}/>);
  expect(screen.getByText(c.refreshing)).toBeVisible(); expect(screen.queryByText(text => text.startsWith(expected[locale][3]))).toBeNull();
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={{ ...p.resource, saving: true }}/>); expect(screen.getByText(c.saving, { selector: 'p' })).toBeVisible();
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={{ ...p.resource, error: null }}/>); expect(screen.queryByText(text => text.startsWith(expected[locale][3]))).toBeNull(); expect(fetch).not.toHaveBeenCalled();
 });
 it('does not enable refresh when device metadata is unavailable', () => {
  setLocale(locale, false); const p = props('authority'); render(<WindowsServiceHealthCompletePanel {...p} metadataReady={false}/>);
  expect(screen.getByRole('button', { name: windowsServiceHealthCompleteCopy[locale].refresh })).toBeDisabled(); expect(screen.getByText(text => text.startsWith(expected[locale][1]))).toBeVisible(); expect(fetch).not.toHaveBeenCalled();
 });
});

// A remembered write notice must not certify a later unavailable assessment.
describe.each(['en', 'de'] as const)('saved notice authority (%s)', locale => {
 it.each(failures)('hides saved after %s and restores only with verified view', error => {
  setLocale(locale, false); const p = props(null), c = windowsServiceHealthCompleteCopy[locale];
  const resource = { ...p.resource, notice: 'saved' as const };
  const rendered = render(<WindowsServiceHealthCompletePanel {...p} resource={resource}/>);
  expect(screen.getByText(c.saved)).toBeVisible();
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={{ ...resource, error }}/>);
  expect(screen.queryByText(c.saved)).toBeNull();
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={resource}/>);
  expect(screen.getByText(c.saved)).toBeVisible(); expect(fetch).not.toHaveBeenCalled(); expect(resource.save).not.toHaveBeenCalled();
 });
 it('hides saved during reads, writes, source loss and metadata/session invalidation', () => {
  setLocale(locale, false); const p = props(null), c = windowsServiceHealthCompleteCopy[locale]; const resource = { ...p.resource, notice: 'saved' as const };
  const rendered = render(<WindowsServiceHealthCompletePanel {...p} resource={resource}/>);
  for (const change of [{ loading: true }, { saving: true }, { view: null }, { elapsedMS: Infinity }]) {
   rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={{ ...resource, ...change }}/>); expect(screen.queryByText(c.saved)).toBeNull();
  }
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={resource} metadataReady={false}/>); expect(screen.queryByText(c.saved)).toBeNull();
  rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={resource} sessionKey={null}/>); expect(screen.queryByText(c.saved)).toBeNull(); expect(fetch).not.toHaveBeenCalled();
 });
 it.each(['uncertain', 'conflict'] as const)('preserves %s without a verified view', notice => {
  setLocale(locale, false); const p = props(null), c = windowsServiceHealthCompleteCopy[locale];
  const rendered = render(<WindowsServiceHealthCompletePanel {...p} resource={{ ...p.resource, notice, view: null }}/>);
  for (const error of [null, ...failures]) {
   rendered.rerender(<WindowsServiceHealthCompletePanel {...p} resource={{ ...p.resource, notice, error, view: null }}/>); expect(screen.getByText(c[notice])).toBeVisible();
  }
  expect(fetch).not.toHaveBeenCalled(); expect(p.resource.save).not.toHaveBeenCalled();
 });
});
