function ipv4(v: string): number[] | null {
    const parts = v.split('.'); return parts.length === 4 && parts.every(p => /^(?:0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255) ? parts.map(Number) : null;
}
/** Canonical numeric netip spelling, parsed locally without URL/DNS interpretation. */
export function numericWindowsAddress(v: unknown, family: 'ipv4' | 'ipv6'): number[] | null {
    if (typeof v !== 'string' || v.length > 45) return null;
    if (family === 'ipv4') return ipv4(v);
    if (!/^[a-f0-9:.]+$/.test(v)) return null;
    let expanded = v;
    if (expanded.includes('.')) {
        const last = expanded.lastIndexOf(':'), tail = ipv4(expanded.slice(last + 1)); if (!tail) return null;
        expanded = expanded.slice(0, last + 1) + ((tail[0] << 8) + tail[1]).toString(16) + ':' + ((tail[2] << 8) + tail[3]).toString(16);
    }
    const sides = expanded.split('::'); if (sides.length > 2) return null;
    const left = sides[0] ? sides[0].split(':') : [], right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
    if (![...left, ...right].every(p => /^[a-f0-9]{1,4}$/.test(p))) return null;
    const missing = 8 - left.length - right.length;
    if (sides.length === 1 ? missing !== 0 : missing < 1) return null;
    const words: number[] = [...left.map(p => parseInt(p, 16)), ...Array(sides.length === 2 ? missing : 0).fill(0), ...right.map(p => parseInt(p, 16))];
    if (words.slice(0, 5).every(n => n === 0) && words[5] === 65535) {
        if (v !== `::ffff:${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`) return null;
    } else {
        let start = -1, length = 1;
        for (let i = 0; i < 8;) { if (words[i] !== 0) { i++; continue; } let end = i; while (end < 8 && words[end] === 0) end++; if (end - i > length) { start = i; length = end - i; } i = end; }
        const hex = words.map(n => n.toString(16));
        if (v !== (start < 0 ? hex.join(':') : hex.slice(0, start).join(':') + '::' + hex.slice(start + length).join(':'))) return null;
    }
    return words.flatMap(n => [n >> 8, n & 255]);
}
