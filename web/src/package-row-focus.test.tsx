import { cleanup, render, screen } from '@testing-library/react';
import type { FocusEvent } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { revealPackageRowSummary } from './package-row-focus';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('package row focus reveal', () => {
    function fixture() {
        render(<><button>Previous control</button><details><summary onFocus={revealPackageRowSummary}>Source package<span> label</span><button>Nested control</button></summary><p>Mapping evidence</p></details></>);
        const summary = document.querySelector('summary')!;
        const reveal = vi.fn(function (this: HTMLElement, options: ScrollIntoViewOptions) {
            expect(this).toBe(summary);
            expect(document.activeElement).toBe(summary);
            expect(options).toEqual({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
        });
        Object.defineProperty(summary, 'scrollIntoView', { configurable: true, value: reveal });
        return { summary, reveal };
    }
    it('reveals synchronously on actual focus with nearest edges and no animated movement', () => {
        const { summary, reveal } = fixture();
        const before = screen.getByRole('button', { name: 'Previous control' });
        before.focus(); expect(reveal).not.toHaveBeenCalled();
        summary.focus(); expect(reveal).toHaveBeenCalledExactlyOnceWith({ block: 'nearest', inline: 'nearest', behavior: 'instant' });
        expect(summary).toHaveFocus(); expect(summary.closest('details')).not.toHaveAttribute('open');
        expect(screen.getByText('Mapping evidence')).not.toBeVisible();
        before.focus(); expect(reveal).toHaveBeenCalledTimes(1);
        summary.focus(); expect(reveal).toHaveBeenCalledTimes(2);
    });
    it('does not reveal the summary for focus bubbling from a nested control', () => {
        const { summary, reveal } = fixture();
        screen.getByRole('button', { name: 'Nested control' }).focus();
        expect(reveal).not.toHaveBeenCalled(); expect(summary).not.toHaveFocus();
        expect(summary.closest('details')).not.toHaveAttribute('open');
    });
    it('does not act on stale focus ownership or schedule a delayed reveal', async () => {
        const { summary, reveal } = fixture();
        screen.getByRole('button', { name: 'Previous control' }).focus();
        const animation = vi.spyOn(window, 'requestAnimationFrame');
        const timeout = vi.spyOn(window, 'setTimeout');
        revealPackageRowSummary({ currentTarget: summary, target: summary } as unknown as FocusEvent<HTMLElement>);
        await Promise.resolve();
        expect(reveal).not.toHaveBeenCalled(); expect(animation).not.toHaveBeenCalled(); expect(timeout).not.toHaveBeenCalled();
        expect(screen.getByRole('button', { name: 'Previous control' })).toHaveFocus();
    });
    it('preserves focus and disclosure when the scroll API is unavailable', () => {
        render(<details><summary onFocus={revealPackageRowSummary}>Source package</summary><p>Mapping evidence</p></details>);
        const summary = document.querySelector('summary')!;
        Object.defineProperty(summary, 'scrollIntoView', { configurable: true, value: undefined });
        summary.focus(); expect(summary).toHaveFocus(); expect(summary.closest('details')).not.toHaveAttribute('open');
    });
});
