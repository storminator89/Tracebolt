/** Presentation only. Never use a display label or suffix as an identity key. */
export function windowsDeviceLabel(deviceId: string, names: ReadonlyMap<string, string>, deviceIds: Iterable<string>, unnamed: string): string {
    const friendlyName = (id: string) => {
        const name = names.get(id)?.trim();
        return name && name !== id ? name : null;
    };
    const name = friendlyName(deviceId) || unnamed;
    const peers = [...new Set(deviceIds)].filter(id => (friendlyName(id) || unnamed) === name);
    if (friendlyName(deviceId) && peers.length < 2) return name;
    let length = 8;
    while (length < deviceId.length && peers.some(id => id !== deviceId && id.slice(-length) === deviceId.slice(-length))) length++;
    return `${name} · ${length < deviceId.length ? '…' : ''}${deviceId.slice(-length)}`;
}
