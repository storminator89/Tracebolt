package systeminventory

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ParseSockets decodes kernel-native 32-bit hex words, preserving actual family
// (including IPv4-mapped IPv6). All supported rows survive, or the whole source
// fails. Endpoint duplicates remain distinct because SO_REUSEPORT is legitimate.
func ParseSockets(ctx context.Context, kind SocketSource, r io.Reader) ([]ObservedSocket, error) {
	if kind != TCP4Source && kind != TCP6Source && kind != UDP4Source && kind != UDP6Source {
		return nil, ErrInvalidInput
	}
	b, e := readBounded(ctx, r)
	if e != nil {
		return nil, e
	}
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 4096), 64<<10)
	if !scan.Scan() {
		return nil, ErrInvalidSource
	}
	h := strings.Fields(scan.Text())
	if len(h) < 12 || h[0] != "sl" || h[1] != "local_address" || (h[2] != "rem_address" && h[2] != "remote_address") || h[3] != "st" || h[11] != "inode" {
		return nil, ErrInvalidSource
	}
	rows := []ObservedSocket{}
	ipv6 := kind == TCP6Source || kind == UDP6Source
	proto := "tcp"
	if kind == UDP4Source || kind == UDP6Source {
		proto = "udp"
	}
	family := "ipv4"
	if ipv6 {
		family = "ipv6"
	}
	for scan.Scan() {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		f := strings.Fields(scan.Text())
		if len(f) < 10 {
			return nil, ErrInvalidSource
		}
		if !strings.HasSuffix(f[0], ":") {
			return nil, ErrInvalidSource
		}
		if _, e := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 10, 32); e != nil {
			return nil, ErrInvalidSource
		}
		local, e := parseEndpoint(f[1], ipv6)
		if e != nil {
			return nil, e
		}
		remote, e := parseEndpoint(f[2], ipv6)
		if e != nil {
			return nil, e
		}
		if len(f[3]) != 2 {
			return nil, ErrInvalidSource
		}
		n, e := strconv.ParseUint(f[3], 16, 8)
		if e != nil {
			return nil, ErrInvalidSource
		}
		// Validate framing of ignored counters/account columns without retaining
		// or exporting their values; this prevents accepting shifted records.
		if !hexPair(f[4], 8, 8) || !hexPair(f[5], 2, 16) || !unsignedToken(f[6], 16, 32) || !unsignedToken(f[7], 10, 32) || !unsignedToken(f[8], 10, 32) {
			return nil, ErrInvalidSource
		}
		inode, e := strconv.ParseUint(f[9], 10, 64)
		if e != nil {
			return nil, ErrInvalidSource
		}
		state := ""
		if proto == "tcp" {
			states := []string{"", "established", "syn-sent", "syn-recv", "fin-wait-1", "fin-wait-2", "time-wait", "closed", "close-wait", "last-ack", "listen", "closing", "new-syn-recv", "bound-inactive"}
			if n == 0 || n >= uint64(len(states)) {
				return nil, ErrInvalidSource
			}
			state = states[n]
		} else {
			switch n {
			case 1:
				state = "connected"
			case 7:
				state = "bound"
				if local.Port == 0 && remote.Port == 0 {
					state = "unbound"
				}
			default:
				return nil, ErrInvalidSource
			}
		}
		socketKind, _ := socketKind(proto, state)
		row := Socket{Protocol: proto, Family: family, Kind: socketKind, Local: local, Remote: remote, State: state, Owners: []Owner{}, Attribution: Attribution{AttributionUnavailable, ReasonNoMatch}}
		if !validSocket(row) {
			return nil, ErrInvalidSource
		}
		rows = append(rows, ObservedSocket{row, inode})
		if len(rows) > MaxSocketRows {
			return nil, ErrItemLimit
		}
	}
	if scan.Err() != nil {
		return nil, ErrSourceLimit
	}
	return rows, nil
}
func parseEndpoint(s string, ipv6 bool) (Endpoint, error) {
	address, port, ok := strings.Cut(s, ":")
	n := 8
	if ipv6 {
		n = 32
	}
	if !ok || len(address) != n || len(port) != 4 {
		return Endpoint{}, ErrInvalidSource
	}
	p, e := strconv.ParseUint(port, 16, 16)
	if e != nil {
		return Endpoint{}, ErrInvalidSource
	}
	var b [16]byte
	for i := 0; i < n/8; i++ {
		word, e := strconv.ParseUint(address[i*8:i*8+8], 16, 32)
		if e != nil {
			return Endpoint{}, ErrInvalidSource
		}
		binary.NativeEndian.PutUint32(b[i*4:i*4+4], uint32(word))
	}
	var a netip.Addr
	if ipv6 {
		a = netip.AddrFrom16(b)
	} else {
		a = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	}
	return Endpoint{a.String(), uint16(p)}, nil
}

func unsignedToken(s string, base, bits int) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	_, err := strconv.ParseUint(s, base, bits)
	return err == nil
}
func hexPair(s string, leftWidth, rightMax int) bool {
	a, b, ok := strings.Cut(s, ":")
	return ok && len(a) == leftWidth && len(b) >= 8 && len(b) <= rightMax && unsignedToken(a, 16, 64) && unsignedToken(b, 16, 64)
}
