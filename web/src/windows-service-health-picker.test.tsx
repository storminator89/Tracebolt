import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useState } from 'react';
import { WindowsServiceHealthPicker } from './windows-service-health-picker';
import { windowsServiceHealthCopy } from './windows-service-health-copy';
afterEach(cleanup);
const choices = [{ name: 'Spooler', displayName: 'Print Spooler' }, { name: 'spooler', displayName: 'Separate exact name' }, { name: ' Worker ü ', displayName: '<script>display only</script>' }];
function Harness({ initial = [] as string[], disabled = false, locale = 'en' as 'en' | 'de', options = choices }) {
    const [selected, setSelected] = useState(initial);
    return <WindowsServiceHealthPicker choices={options} selected={selected} disabled={disabled} onChange={setSelected} c={windowsServiceHealthCopy[locale]}/>;
}
describe('Windows reported service chooser', () => {
    it.each(['en', 'de'] as const)('starts with no implicit selection and shows readable display and exact names in %s', locale => {
        render(<Harness locale={locale}/>); expect(screen.getByText('Print Spooler')).toBeVisible(); expect(screen.getByText('Spooler')).toBeVisible(); expect(screen.getAllByRole('checkbox').every(input => !(input as HTMLInputElement).checked)).toBe(true); expect(screen.getByText(windowsServiceHealthCopy[locale].noSelection)).toBeVisible();
    });
    it('searches display names and exact names without changing selection or executing markup', () => {
        render(<Harness/>); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'print' } }); expect(screen.getAllByRole('checkbox')).toHaveLength(1); fireEvent.click(screen.getByRole('checkbox')); fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'ü' } }); expect(screen.getByText('<script>display only</script>')).toBeVisible(); fireEvent.click(screen.getByRole('checkbox')); expect(screen.getByRole('button', { name: 'Remove service: Worker ü' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Remove service: Spooler' })).toBeVisible(); expect(screen.getByRole('button', { name: 'Remove service: Worker ü' })).toHaveAttribute('aria-label', 'Remove service:  Worker ü '); expect(document.querySelector('script')).toBeNull();
    });
    it('treats case-distinct service names as separate opaque selectors', () => {
        const onChange = vi.fn(); render(<WindowsServiceHealthPicker choices={choices} selected={['Spooler']} disabled={false} onChange={onChange} c={windowsServiceHealthCopy.en}/>); fireEvent.click(screen.getByRole('checkbox', { name: /Separate exact name/ })); expect(onChange).toHaveBeenCalledWith(['Spooler', 'spooler']);
    });
    it('enforces eight selections while allowing removals and later additions', () => {
        const options = Array.from({ length: 9 }, (_, i) => ({ name: `svc${i}`, displayName: `Readable service ${i}` })); render(<Harness options={options} initial={options.slice(0, 8).map(row => row.name)}/>); expect(screen.getByRole('checkbox', { name: /Readable service 8/ })).toBeDisabled(); fireEvent.click(screen.getByRole('button', { name: 'Remove service: svc0' })); expect(screen.getByRole('checkbox', { name: /Readable service 8/ })).toBeEnabled(); fireEvent.click(screen.getByRole('checkbox', { name: /Readable service 8/ })); expect(screen.getByRole('checkbox', { name: /Readable service 0/ })).toBeDisabled();
    });
    it('withholds ambiguous duplicate names rather than using a last-wins map', () => {
        render(<Harness options={[...choices, { name: 'Spooler', displayName: 'Conflicting name' }]} initial={['Spooler']}/>); expect(screen.queryByRole('checkbox', { name: /Print Spooler/ })).toBeNull(); expect(screen.queryByRole('checkbox', { name: /Conflicting name/ })).toBeNull(); expect(screen.getByText('Not in the current reported choices')).toBeVisible(); expect(screen.getByRole('button', { name: 'Remove service: Spooler' })).toBeEnabled();
    });
    it('keeps saved names visible and removable when no source choices are available', () => {
        render(<Harness initial={['MissingService']} options={[]}/>); expect(screen.getByText('MissingService')).toBeVisible(); expect(screen.getByText(/Absence is not proof/)).toBeVisible(); fireEvent.click(screen.getByRole('button', { name: 'Remove service: MissingService' })); expect(screen.queryByText('MissingService')).toBeNull();
    });
    it('does not submit an enclosing policy form on search Enter', () => {
        const submit = vi.fn(event => event.preventDefault()); render(<form onSubmit={submit}><Harness/></form>); fireEvent.keyDown(screen.getByRole('searchbox'), { key: 'Enter' }); expect(submit).not.toHaveBeenCalled();
    });
    it('disables editing for a read-only or unverified policy', () => {
        render(<Harness initial={['Spooler']} disabled/>); expect(screen.getByRole('searchbox')).toBeDisabled(); expect(screen.getAllByRole('checkbox').every(input => (input as HTMLInputElement).disabled)).toBe(true); expect(screen.getByRole('button', { name: 'Remove service: Spooler' })).toBeDisabled();
    });
});
