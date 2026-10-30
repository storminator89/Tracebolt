import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { FocusEvent } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { revealCompletePackageRegion } from './complete-package-focus';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('complete package region focus reveal', () => {
    function fixture(indicatesFocus = true) {
        render(<><details><summary>Capture details</summary><p>Capture evidence</p></details><div role="region" aria-label="Complete packages" tabIndex={0} onFocus={revealCompletePackageRegion}><details><summary>Package mapping</summary><p>Mapping evidence</p></details></div><button>Next page</button></>);
        const region = screen.getByRole('region', { name: 'Complete packages' });
        // jsdom does not implement native input-modality or scrolling geometry.
        const nativeMatches = region.matches.bind(region);
        const matches = vi.fn((_selector: string) => indicatesFocus);
        vi.spyOn(region, 'matches').mockImplementation(selector => selector === ':focus-visible' ? matches(selector) : nativeMatches(selector));
        const reveal = vi.fn(function (this: HTMLElement, options: ScrollIntoViewOptions) {
            expect(this).toBe(region); expect(document.activeElement).toBe(region);
            expect(options).toEqual({ block: 'start', inline: 'nearest', behavior: 'instant' });
        });
        Object.defineProperty(region, 'scrollIntoView', { configurable: true, value: reveal });
        return { region, matches, reveal };
    }
    it('reveals the indicated region synchronously without changing focus, disclosure, or its own scroll offsets', () => {
        const { region, reveal } = fixture();
        region.scrollLeft = 83; region.scrollTop = 19;
        region.focus();
        expect(reveal).toHaveBeenCalledExactlyOnceWith({ block: 'start', inline: 'nearest', behavior: 'instant' });
        expect(region).toHaveFocus(); expect(region.scrollLeft).toBe(83); expect(region.scrollTop).toBe(19);
        for (const details of document.querySelectorAll('details')) expect(details).not.toHaveAttribute('open');
        expect(screen.getByText('Mapping evidence')).not.toBeVisible();
    });
    it('keeps DOM focus order and leaves native Tab, Shift+Tab and arrow-key events alone', () => {
        const { region, reveal } = fixture();
        const capture = screen.getByText('Capture details'), mapping = screen.getByText('Package mapping');
        expect(capture.compareDocumentPosition(region) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(region.compareDocumentPosition(mapping) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
        expect(region).toHaveAttribute('tabindex', '0'); expect(capture).not.toHaveAttribute('tabindex'); expect(mapping).not.toHaveAttribute('tabindex');
        region.focus(); expect(reveal).toHaveBeenCalledTimes(1);
        for (const options of [{ key: 'Tab' }, { key: 'Tab', shiftKey: true }, { key: 'ArrowRight' }, { key: 'ArrowDown' }]) {
            const key = new KeyboardEvent('keydown', { ...options, bubbles: true, cancelable: true });
            expect(region.dispatchEvent(key)).toBe(true); expect(key.defaultPrevented).toBe(false);
        }
        expect(region).toHaveFocus(); expect(reveal).toHaveBeenCalledTimes(1);
        mapping.focus(); expect(mapping).toHaveFocus(); expect(reveal).toHaveBeenCalledTimes(1);
        region.focus(); expect(region).toHaveFocus(); expect(reveal).toHaveBeenCalledTimes(2);
        capture.focus(); expect(capture).toHaveFocus(); expect(reveal).toHaveBeenCalledTimes(2);
    });
    it('does not reveal ordinary pointer-style focus without a focus-visible indication', () => {
        const { region, matches, reveal } = fixture(false);
        fireEvent.pointerDown(region); region.focus(); fireEvent.pointerUp(region);
        expect(region).toHaveFocus(); expect(matches).toHaveBeenCalledExactlyOnceWith(':focus-visible'); expect(reveal).not.toHaveBeenCalled();
    });
    it('does not reveal the region for focus bubbling from a package summary', () => {
        const { region, matches, reveal } = fixture();
        screen.getByText('Package mapping').focus();
        expect(region).not.toHaveFocus(); expect(matches).not.toHaveBeenCalled(); expect(reveal).not.toHaveBeenCalled();
    });
    it('ignores stale ownership and never defers the reveal after focus changes', async () => {
        const { region, matches, reveal } = fixture();
        const capture = screen.getByText('Capture details'); capture.focus();
        const staleAnimation = vi.spyOn(window, 'requestAnimationFrame'), staleTimeout = vi.spyOn(window, 'setTimeout');
        revealCompletePackageRegion({ currentTarget: region, target: region } as unknown as FocusEvent<HTMLElement>);
        expect(matches).not.toHaveBeenCalled(); expect(reveal).not.toHaveBeenCalled();
        expect(staleAnimation).not.toHaveBeenCalled(); expect(staleTimeout).not.toHaveBeenCalled();
        staleAnimation.mockRestore(); staleTimeout.mockRestore();
        region.focus(); expect(reveal).toHaveBeenCalledTimes(1); reveal.mockClear();
        // Spy on the helper itself, excluding jsdom's own focus-event scheduling.
        const animation = vi.spyOn(window, 'requestAnimationFrame'), timeout = vi.spyOn(window, 'setTimeout');
        revealCompletePackageRegion({ currentTarget: region, target: region } as unknown as FocusEvent<HTMLElement>);
        expect(reveal).toHaveBeenCalledTimes(1); expect(animation).not.toHaveBeenCalled(); expect(timeout).not.toHaveBeenCalled();
        animation.mockRestore(); timeout.mockRestore();
        capture.focus(); await Promise.resolve();
        expect(capture).toHaveFocus(); expect(reveal).toHaveBeenCalledTimes(1);
    });
    it('preserves focus when the scrolling API is unavailable', () => {
        const { region } = fixture();
        Object.defineProperty(region, 'scrollIntoView', { configurable: true, value: undefined });
        region.focus(); expect(region).toHaveFocus();
    });
});
