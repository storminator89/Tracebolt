import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { WindowsLocalTime } from './windows-local-time';

afterEach(cleanup);
describe('compact local Windows timestamps', () => {
    it.each(['en', 'de'])('shows the local date and UTC offset in %s without changing the original instant', locale => {
        const value = '2026-10-07T12:30:10.123456789Z', language = locale === 'de' ? 'de-DE' : 'en-GB';
        const { container } = render(<WindowsLocalTime value={value} locale={locale}/>);
        const time = container.querySelector('time')!;
        expect(time).toHaveAttribute('datetime', value); expect(time).toHaveAttribute('title', value);
        expect(time).toHaveTextContent(new Intl.DateTimeFormat(language, { day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(value)));
        expect(time).toHaveTextContent(new Intl.DateTimeFormat(language, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'shortOffset' }).format(new Date(value)));
        expect(time).toHaveTextContent(/GMT/); expect(time).not.toHaveTextContent(value);
        expect(time.querySelectorAll('span')).toHaveLength(2);
    });
    it('preserves the complete source timestamp in exact detail', () => {
        const value = '2026-10-07T12:30:10.123456789Z'; render(<WindowsLocalTime value={value} locale="de" exact/>);
        expect(screen.getByText(value)).toHaveAttribute('datetime', value);
    });
});
