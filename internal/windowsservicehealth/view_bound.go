package windowsservicehealth

// The view combines a bounded durable ledger with up to one existing 48 KiB
// accepted service inventory. Leave room for maximum escaped names in history,
// eight checks, and that chooser without silently dropping additional rows.
const MaxViewBytes = 512 << 10
