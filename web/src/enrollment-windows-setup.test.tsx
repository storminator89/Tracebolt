import type {} from 'vitest/jsdom';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WindowsSetupPreparation } from './enrollment-windows-setup';
import { checkWindowsSetupFile, WINDOWS_SETUP_RELEASE as pin } from './windows-setup-release';
import { setLocale } from './i18n';

const matchedDigest = Uint8Array.from(pin.sha256.match(/../g)!, byte => parseInt(byte, 16)).buffer;
const bytes = new ArrayBuffer(pin.size);
function file(overrides = {}) { return { name: pin.name, size: pin.size, arrayBuffer: vi.fn().mockResolvedValue(bytes), ...overrides }; }
function choose(value: ReturnType<typeof file>) { fireEvent.change(screen.getByLabelText('Check downloaded Setup (optional)'), { target: { files: [value] } }); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Pinned local Windows Setup file check', () => {
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
});
