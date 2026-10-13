package macosinventory

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

func sourceLines(raw []byte) ([]string, error) {
	lines, err := sourceByteLines(raw)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, ErrMetadata
	}
	return lines, nil
}

// The process source frames raw p_comm bytes before validating its label. A
// kernel name can end midway through a UTF-8 code point; this must not discard
// valid PID/parent-PID fields or independently valid process rows.
func sourceByteLines(raw []byte) ([]string, error) {
	if len(raw) > MaxSourceBytes {
		return nil, ErrBounds
	}
	if bytes.ContainsAny(raw, "\x00\r") {
		return nil, ErrMetadata
	}
	if len(raw) == 0 {
		return []string{}, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, ErrMetadata
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	for _, line := range lines {
		if len(line) > 4096 {
			return nil, ErrBounds
		}
	}
	return lines, nil
}
func decimal(s string, bits int) (uint64, error) {
	if s == "" {
		return 0, ErrMetadata
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, ErrMetadata
		}
	}
	n, e := strconv.ParseUint(s, 10, bits)
	if e != nil {
		return 0, ErrMetadata
	}
	return n, nil
}
func ParseHardware(raw []byte) (Hardware, error) {
	lines, e := sourceLines(raw)
	if e != nil {
		return Hardware{}, e
	}
	if len(lines) != 4 {
		return Hardware{}, ErrMetadata
	}
	physical, e1 := decimal(lines[1], 32)
	logical, e2 := decimal(lines[2], 32)
	memory, e3 := decimal(lines[3], 64)
	h := Hardware{Status: Status{HardwareSource, "observed", ""}, ModelIdentifier: lines[0], PhysicalCPUs: uint32(physical), LogicalCPUs: uint32(logical), MemoryCapacityBytes: memory}
	if e1 != nil || e2 != nil || e3 != nil || !validHardware(h) {
		return Hardware{}, ErrMetadata
	}
	return h, nil
}
func ParseProcesses(raw []byte) (Processes, error) {
	lines, e := sourceByteLines(raw)
	if e != nil {
		return Processes{}, e
	}
	if len(lines) > MaxProcesses {
		return Processes{}, ErrBounds
	}
	rows := make([]Process, 0, len(lines))
	for _, line := range lines {
		// Apple's ucomm is a fixed MAXCOMLEN (16-byte) first column, without
		// argument-space access. Its position/width also makes embedded newlines
		// fail closed instead of allowing a name to forge a new process row.
		if len(line) < 20 || line[16] != ' ' {
			return Processes{}, ErrMetadata
		}
		columns := strings.Fields(line[17:])
		if len(columns) != 2 {
			return Processes{}, ErrMetadata
		}
		pid, e1 := decimal(columns[0], 31)
		ppid, e2 := decimal(columns[1], 31)
		if e1 != nil || e2 != nil {
			return Processes{}, ErrMetadata
		}
		name := strings.Trim(line[:16], " ")
		quality := "observed"
		if !accountingName(name) {
			name = ""
			quality = "unavailable"
		}
		rows = append(rows, Process{uint32(pid), uint32(ppid), name, quality})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].PID < rows[j].PID })
	p := Processes{Status{ProcessSource, "observed", ""}, rows}
	if !validProcesses(p) {
		return Processes{}, ErrMetadata
	}
	return p, nil
}
func parseHeader(line string) (Interface, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasSuffix(fields[0], ":") || !strings.HasPrefix(fields[1], "flags=") {
		return Interface{}, ErrMetadata
	}
	name := strings.TrimSuffix(fields[0], ":")
	flagText := strings.TrimPrefix(fields[1], "flags=")
	open := strings.IndexByte(flagText, '<')
	if open < 1 || !strings.HasSuffix(flagText, ">") {
		return Interface{}, ErrMetadata
	}
	flags, e := strconv.ParseUint(flagText[:open], 16, 32)
	if e != nil {
		return Interface{}, ErrMetadata
	}
	var mtu uint64
	count := 0
	for i, s := range fields {
		if s == "mtu" {
			count++
			if i+1 >= len(fields) {
				return Interface{}, ErrMetadata
			}
			mtu, e = decimal(fields[i+1], 32)
			if e != nil {
				return Interface{}, e
			}
		}
	}
	if count != 1 || !token(name, 15, "._-") || mtu == 0 || mtu > 1<<20 {
		return Interface{}, ErrMetadata
	}
	return Interface{Name: name, MTU: uint32(mtu), Up: flags&1 != 0, Running: flags&0x40 != 0, Addresses: []Address{}}, nil
}
func parseAddress(line, name string, ipv6 bool) (Address, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Address{}, ErrMetadata
	}
	want := "inet"
	prefixKey := "netmask"
	if ipv6 {
		want = "inet6"
		prefixKey = "prefixlen"
	}
	if fields[0] != want {
		return Address{}, ErrMetadata
	}
	ip, e := netip.ParseAddr(fields[1])
	if e != nil || ip.Is6() != ipv6 || ip.Is4In6() {
		return Address{}, ErrMetadata
	}
	if ip.Zone() != "" && ip.Zone() != name {
		return Address{}, ErrMetadata
	}
	ip = ip.WithZone("")
	count := 0
	var bits uint64
	for i, s := range fields {
		if s != prefixKey {
			continue
		}
		count++
		if i+1 >= len(fields) {
			return Address{}, ErrMetadata
		}
		if ipv6 {
			bits, e = decimal(fields[i+1], 8)
			if e != nil || bits > 128 {
				return Address{}, ErrMetadata
			}
		} else {
			mask := fields[i+1]
			if len(mask) < 3 || len(mask) > 10 || !strings.HasPrefix(mask, "0x") {
				return Address{}, ErrMetadata
			}
			n, e := strconv.ParseUint(mask[2:], 16, 32)
			if e != nil {
				return Address{}, ErrMetadata
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(n))
			ones, width := net.IPMask(b[:]).Size()
			if width != 32 {
				return Address{}, ErrMetadata
			}
			bits = uint64(ones)
		}
	}
	if count != 1 {
		return Address{}, ErrMetadata
	}
	return Address{ip.String(), uint8(bits)}, nil
}

// ParseInterfaces projects only the requested family. Well-formed address
// records of the other family and unselected indented OS metadata are discarded
// without being copied into the result. Unknown top-level records, malformed
// address records and duplicate selected identities fail the source.
func ParseInterfaces(raw []byte, ipv6 bool) (Interfaces, error) {
	source := IPv4Source
	if ipv6 {
		source = IPv6Source
	}
	lines, e := sourceLines(raw)
	if e != nil {
		return Interfaces{}, e
	}
	rows := []Interface{}
	for _, line := range lines {
		if line == "" {
			return Interfaces{}, ErrMetadata
		}
		if line[0] != ' ' && line[0] != '\t' {
			if len(rows) >= MaxInterfaces {
				return Interfaces{}, ErrBounds
			}
			r, e := parseHeader(line)
			if e != nil {
				return Interfaces{}, e
			}
			rows = append(rows, r)
			continue
		}
		if len(rows) == 0 {
			return Interfaces{}, ErrMetadata
		}
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			return Interfaces{}, ErrMetadata
		}
		if fields[0] != "inet" && fields[0] != "inet6" {
			continue
		}
		row := &rows[len(rows)-1]
		lineIPv6 := fields[0] == "inet6"
		a, e := parseAddress(trimmed, row.Name, lineIPv6)
		if e != nil {
			return Interfaces{}, e
		}
		// ifconfig emits CLAT46 inet6 metadata even when inet was selected.
		// Validate but discard the other family: it is not evidence for this
		// result, nor does it establish a successful opposite-family read.
		if lineIPv6 != ipv6 {
			continue
		}
		if len(row.Addresses) >= MaxAddresses {
			return Interfaces{}, ErrBounds
		}
		row.Addresses = append(row.Addresses, a)
	}
	v := Interfaces{Status{source, "observed", ""}, rows}
	sortInterfaces(&v)
	if !validInterfaces(v, source, ipv6) {
		return Interfaces{}, ErrMetadata
	}
	return v, nil
}
