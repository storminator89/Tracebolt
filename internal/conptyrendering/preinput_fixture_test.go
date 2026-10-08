package conptyrendering

import (
	"bytes"
	"localrmm/internal/windowsacceptance/freshgate"
)

// Fixed public fixtures. No value describes a real host or issued invitation.
const publicInventoryDisclosure = "Windows inventory includes the local hostname, interface names and IP addresses; caller-visible process IDs, parent IDs, names and thread counts; service names, display names, states and PIDs; machine uninstall software names, versions, publishers and registry views; and OS, uptime, CPU, physical RAM and system-volume metrics. These fields can reveal private names, installed software and network topology. Rows are bounded and may be partial, denied or unavailable; counts cover only the reported local API scope. No command lines, executable paths, owners, process memory, MAC addresses, DNS, routes, sockets, event content, remote actions or updates are included. A fresh explicitly acknowledged Windows identity is required; existing basic or Linux ledgers cannot be adopted or reset. Production TLS is the default; disposable HTTP test transport requires an additional explicit plaintext acknowledgement. Inventory stays in the operator view and is excluded from AI export."
const publicDisclosureLines = "Manager: public-fixture\r\nEnrollment: https://example.invalid/enroll\r\nAgent ingress: https://example.invalid/agent\r\nScope: windows-inventory-v1\r\n" + publicInventoryDisclosure + "\r\nServer CA SHA-256: " + publicFingerprint + "\r\nIssuer root SHA-256: " + publicFingerprint + "\r\nIssuer SHA-256: " + publicFingerprint + "\r\n"
const publicComparisonReminder = "Compare the complete public fingerprint and comparison value in the manager before approving.\r\n"

type preinputResult struct {
	live, trust, ready, restored bool
	rejection                    freshgate.OutputRejection
	firstCSI                     string
}

// Classification only, never permission. All parameters remain private to the
// bounded public observer; only these finite semantic labels leave the fixture.
func publicCSISignature(p []byte, final byte) string {
	if bytes.Equal(p, []byte("?12")) {
		if final == 'h' {
			return "cursor_blink_enable"
		}
		if final == 'l' {
			return "cursor_blink_disable"
		}
	}
	if final == 'q' {
		switch string(p) {
		case " ", "0 ":
			return "cursor_style_default"
		case "1 ":
			return "cursor_style_blink_block"
		case "2 ":
			return "cursor_style_steady_block"
		case "3 ":
			return "cursor_style_blink_underline"
		case "4 ":
			return "cursor_style_steady_underline"
		case "5 ":
			return "cursor_style_blink_bar"
		case "6 ":
			return "cursor_style_steady_bar"
		}
	}
	if final == 'K' {
		switch string(p) {
		case "":
			return "erase_line_default"
		case "0":
			return "erase_line_right"
		case "2":
			return "erase_line_all"
		}
	}
	switch final {
	case 'H', 'f':
		return "cursor_position"
	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'd':
		return "cursor_movement"
	case 'm':
		return "sgr"
	}
	return "other"
}
