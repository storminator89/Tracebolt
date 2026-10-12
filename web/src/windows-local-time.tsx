import './windows-local-time.css';

/** Presentation only: the original instant remains unchanged in datetime and exact detail. */
export function WindowsLocalTime({ value, locale, exact = false }: { value: string; locale: string; exact?: boolean }) {
    if (exact) return <time className="windows-exact-time" dateTime={value}>{value}</time>;
    const language = locale === 'de' ? 'de-DE' : 'en-GB', instant = new Date(value);
    const date = new Intl.DateTimeFormat(language, { day: 'numeric', month: 'short', year: 'numeric' }).format(instant);
    const clock = new Intl.DateTimeFormat(language, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZoneName: 'shortOffset' }).format(instant);
    return <time className="windows-local-time" dateTime={value} title={value}><span>{date}</span>{' · '}<span>{clock}</span></time>;
}
