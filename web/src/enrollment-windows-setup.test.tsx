import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WindowsSetupInstructions, WindowsSetupPreparation } from './enrollment-windows-setup';
import { checkWindowsSetupFile, WINDOWS_SETUP_LINKS, WINDOWS_SETUP_RELEASE as pin } from './windows-setup-release';
import { setLocale } from './i18n';

const matchedDigest = Uint8Array.from(pin.sha256.match(/../g)!, byte => parseInt(byte, 16)).buffer;
const bytes = new ArrayBuffer(pin.size);
function file(overrides = {}) { return { name: pin.name, size: pin.size, arrayBuffer: vi.fn().mockResolvedValue(bytes), ...overrides }; }
function choose(value: ReturnType<typeof file>) { fireEvent.change(screen.getByLabelText('Check downloaded Setup (optional)'), { target: { files: [value] } }); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Pinned local Windows Setup file check', () => {
 it.each(['en', 'de'] as const)('shows the exact expected file in labeled preparation sections (%s)', locale => {
  setLocale(locale, false); const network = vi.fn(); vi.stubGlobal('fetch', network);
  render(<WindowsSetupPreparation insecureTest={false}/>);
  const download = screen.getByRole('region', { name: locale === 'de' ? '1. Windows-Setup herunterladen' : '1. Download Windows Setup' });
  const check = screen.getByRole('region', { name: locale === 'de' ? '2. Lokale Datei prüfen' : '2. Check the local file' });
  expect(within(download).getByText(pin.name)).toBeVisible();
  expect(within(download).getByText(`${pin.size.toLocaleString(locale)} ${locale === 'de' ? 'Bytes' : 'bytes'}`)).toBeVisible();
  const link = within(download).getByRole('link', { name: locale === 'de' ? 'Setup herunterladen · Preview.3' : 'Download Setup · preview.3' });
  expect(link).toHaveAttribute('href', WINDOWS_SETUP_LINKS.setup); expect(link).toHaveAttribute('rel', 'noopener noreferrer'); expect(link).toHaveAttribute('referrerpolicy', 'no-referrer');
  const input = within(check).getByLabelText(locale === 'de' ? 'Heruntergeladenes Setup prüfen (optional)' : 'Check downloaded Setup (optional)');
  expect(input).toHaveAttribute('accept', '.exe'); expect(input).toHaveAccessibleDescription(expect.stringContaining(pin.name));
  expect(input).toHaveAccessibleDescription(expect.stringContaining(locale === 'de' ? 'weder hochgeladen noch ausgeführt' : 'never uploaded or run'));
  expect(screen.getByText(locale === 'de' ? /Unsignierter x64-Preview/ : /Unsigned x64 preview/)).toBeVisible();
  expect(document.querySelectorAll('svg:not([aria-hidden="true"])')).toHaveLength(0);
  expect(network).not.toHaveBeenCalled(); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
 });
 it('checks exact size and name before reading any contents', async () => {
  for (const value of [file({ name: 'invitation.json' }), file({ size: pin.size + 1 }), file({ size: 0 })]) {
   expect(await checkWindowsSetupFile(value)).toBe('different-file'); expect(value.arrayBuffer).not.toHaveBeenCalled();
  }
 });
 it('matches only the selected SHA-256 and reads the complete bounded image once', async () => {
  const digest = vi.fn().mockResolvedValue(matchedDigest); vi.stubGlobal('crypto', { subtle: { digest } });
  const value = file(); expect(await checkWindowsSetupFile(value)).toBe('matched');
  expect(value.arrayBuffer).toHaveBeenCalledTimes(1); expect(digest).toHaveBeenCalledExactlyOnceWith('SHA-256', bytes);
  digest.mockResolvedValue(new Uint8Array(32).buffer); expect(await checkWindowsSetupFile(file())).toBe('different-file');
  digest.mockResolvedValue(matchedDigest); expect(await checkWindowsSetupFile(file({ arrayBuffer: async () => new ArrayBuffer(1) }))).toBe('different-file');
  expect(digest).toHaveBeenCalledTimes(2);
 });
 it('fails closed when WebCrypto, file reads or digest operations are unavailable', async () => {
  vi.stubGlobal('crypto', {}); const value = file(); expect(await checkWindowsSetupFile(value)).toBe('unavailable'); expect(value.arrayBuffer).not.toHaveBeenCalled();
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockRejectedValue(new Error('private-native-error')) } });
  expect(await checkWindowsSetupFile(file())).toBe('failed');
  expect(await checkWindowsSetupFile(file({ arrayBuffer: async () => { throw new Error('private-path'); } }))).toBe('failed');
 });
 it('shows byte identity without granting publisher trust or persisting the result', async () => {
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  const network = vi.fn(); vi.stubGlobal('fetch', network);
  render(<WindowsSetupPreparation insecureTest={false}/>); choose(file());
  expect(await screen.findByRole('status')).toHaveTextContent('It remains unsigned'); expect(screen.getByRole('status')).toHaveTextContent('not publisher trust or permission to install');
  expect(network).not.toHaveBeenCalled(); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
 });
 it('never lets an older success replace a newer failed selection', async () => {
  let finish!: (value: ArrayBuffer) => void;
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  render(<WindowsSetupPreparation insecureTest={false}/>);
  choose(file({ arrayBuffer: () => new Promise<ArrayBuffer>(resolve => { finish = resolve; }) }));
  expect(screen.getByRole('status')).toHaveTextContent('Checking'); choose(file({ name: 'other.exe' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('does not match');
  await act(async () => { finish(bytes); });
  expect(screen.getByRole('alert')).toHaveTextContent('does not match'); expect(screen.queryByRole('status')).not.toBeInTheDocument();
 });
 it('allows a deliberate recheck after a file read failure and discards work after closing', async () => {
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  const view = render(<WindowsSetupPreparation insecureTest={false}/>);
  choose(file({ arrayBuffer: async () => { throw new Error('private-file-path'); } }));
  expect(await screen.findByRole('alert')).toHaveTextContent('could not be checked'); expect(document.body.textContent).not.toContain('private-file-path');
  choose(file()); expect(await screen.findByRole('status')).toHaveTextContent('File matches');
  let finish!: (value: ArrayBuffer) => void;
  choose(file({ arrayBuffer: () => new Promise<ArrayBuffer>(resolve => { finish = resolve; }) })); view.unmount();
  await act(async () => { finish(bytes); }); expect(screen.queryByRole('status')).not.toBeInTheDocument();
 });
 it('clears a previous match when switching transport and requires a fresh deliberate file check', async () => {
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  const view = render(<WindowsSetupPreparation insecureTest={false}/>); choose(file());
  expect(await screen.findByRole('status')).toHaveTextContent('File matches');
  view.rerender(<WindowsSetupPreparation insecureTest/>);
  expect(screen.getByText(/Published preview.3 is TLS-only/)).toBeVisible();
  expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Check downloaded Setup (optional)')).not.toBeInTheDocument();
  view.rerender(<WindowsSetupPreparation insecureTest={false}/>);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  choose(file()); expect(await screen.findByRole('status')).toHaveTextContent('File matches');
 });
 it('ignores a late check across a transport switch even after a new TLS check starts', async () => {
  let finish!: (value: ArrayBuffer) => void;
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  const view = render(<WindowsSetupPreparation insecureTest={false}/>);
  choose(file({ arrayBuffer: () => new Promise<ArrayBuffer>(resolve => { finish = resolve; }) }));
  expect(screen.getByRole('status')).toHaveTextContent('Checking');
  view.rerender(<WindowsSetupPreparation insecureTest/>); view.rerender(<WindowsSetupPreparation insecureTest={false}/>);
  choose(file({ name: 'different.exe' })); expect(await screen.findByRole('alert')).toHaveTextContent('does not match');
  await act(async () => { finish(bytes); });
  expect(screen.getByRole('alert')).toHaveTextContent('does not match'); expect(screen.queryByRole('status')).not.toBeInTheDocument();
 });
 it('does not restore a check that completed while the TLS preparation was hidden', async () => {
  let finish!: (value: ArrayBuffer) => void;
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  const view = render(<WindowsSetupPreparation insecureTest={false}/>);
  choose(file({ arrayBuffer: () => new Promise<ArrayBuffer>(resolve => { finish = resolve; }) }));
  view.rerender(<WindowsSetupPreparation insecureTest/>);
  await act(async () => { finish(bytes); }); expect(screen.queryByRole('status')).not.toBeInTheDocument();
  view.rerender(<WindowsSetupPreparation insecureTest={false}/>);
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
 });
 it('clears the result when a file selection is empty', async () => {
  vi.stubGlobal('crypto', { subtle: { digest: vi.fn().mockResolvedValue(matchedDigest) } });
  render(<WindowsSetupPreparation insecureTest={false}/>); choose(file()); await screen.findByRole('status');
  fireEvent.change(screen.getByLabelText('Check downloaded Setup (optional)'), { target: { files: [] } });
  expect(screen.queryByRole('status')).not.toBeInTheDocument(); expect(screen.queryByRole('alert')).not.toBeInTheDocument();
 });
});

describe('Windows installation instructions', () => {
 it.each(['en', 'de'] as const)('separates the four locations and preserves all safety instructions without actions (%s)', locale => {
  setLocale(locale, false); const network = vi.fn(); vi.stubGlobal('fetch', network);
  render(<WindowsSetupInstructions/>);
  const region = screen.getByRole('region', { name: locale === 'de' ? 'Windows installieren und prüfen' : 'Install and verify Windows' });
  const steps = within(region).getAllByRole('listitem'); expect(steps).toHaveLength(4);
  const titles = locale === 'de' ? ['Öffentliche Konfiguration öffnen', 'Lokale Berechtigungen prüfen', 'Geräteidentität vergleichen', 'Ersten Bericht prüfen'] : ['Open the public configuration', 'Review local permissions', 'Compare the device identity', 'Verify the first report'];
  steps.forEach((step, index) => expect(within(step).getByRole('heading', { name: titles[index], level: 4 })).toBeVisible());
  expect(steps[0]).toHaveTextContent(locale === 'de' ? 'Auf dem Windows-Gerät' : 'On the Windows device');
  expect(steps[1]).toHaveTextContent(locale === 'de' ? 'Im Windows-Setup' : 'In Windows Setup');
  expect(steps[1]).toHaveTextContent(locale === 'de' ? 'Diese Dashboard-Einladung gewährt diese Bereiche nicht.' : 'This dashboard invitation does not grant those scopes.');
  expect(steps[2]).toHaveTextContent(locale === 'de' ? 'separaten verdeckten Setup-Konsole' : 'separate hidden-input console');
  expect(steps[3]).toHaveTextContent(locale === 'de' ? 'allein belegen keine Berichterfassung' : 'alone does not prove reporting');
  expect(within(region).getByRole('heading', { name: locale === 'de' ? 'Setup abgebrochen?' : 'Setup interrupted?' })).toBeVisible();
  expect(region).toHaveTextContent(locale === 'de' ? 'den Zustand für die Administratorprüfung erhalten' : 'retain all state for administrator review');
  expect(document.querySelectorAll('svg:not([aria-hidden="true"])')).toHaveLength(0);
  expect(screen.queryByRole('button')).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument(); expect(screen.queryByRole('link')).not.toBeInTheDocument();
  expect(network).not.toHaveBeenCalled(); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
 });
});
