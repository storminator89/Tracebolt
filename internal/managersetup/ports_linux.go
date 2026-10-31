//go:build linux

package managersetup

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"localrmm/internal/lanconfig"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type listener struct{ address netip.AddrPort }

var errPorts = errors.New("listener snapshot unavailable")

// Reading procfs is deliberately used instead of bind/listen/connect probes.
// A successful snapshot cannot reserve a port or prove Docker host publication.
func readListeners() ([]listener, error) {
	var all []listener
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			return nil, errPorts
		}
		raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		closeErr := f.Close()
		if err != nil || closeErr != nil || len(raw) > 4<<20 {
			return nil, errPorts
		}
		rows, err := parseListeners(raw)
		if err != nil {
			return nil, err
		}
		all = append(all, rows...)
	}
	return all, nil
}

func parseListeners(raw []byte) ([]listener, error) {
	s := bufio.NewScanner(bytes.NewReader(raw))
	if !s.Scan() || !strings.Contains(s.Text(), "local_address") || !strings.Contains(s.Text(), "st") {
		return nil, errPorts
	}
	var rows []listener
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			return nil, errPorts
		}
		if fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 || (len(parts[0]) != 8 && len(parts[0]) != 32) || len(parts[1]) != 4 {
			return nil, errPorts
		}
		port, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil || port == 0 {
			return nil, errPorts
		}
		ip := make([]byte, len(parts[0])/2)
		for i := 0; i < len(ip); i += 4 {
			word, err := strconv.ParseUint(parts[0][i*2:i*2+8], 16, 32)
			if err != nil {
				return nil, errPorts
			}
			binary.NativeEndian.PutUint32(ip[i:i+4], uint32(word))
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, errPorts
		}
		rows = append(rows, listener{netip.AddrPortFrom(addr.Unmap(), uint16(port))})
	}
	if s.Err() != nil {
		return nil, errPorts
	}
	return rows, nil
}

func overlapping(a, b netip.AddrPort) bool {
	if a.Port() != b.Port() {
		return false
	}
	aa, ba := a.Addr().Unmap(), b.Addr().Unmap()
	if aa == ba {
		return true
	}
	// An IPv6 wildcard can also own IPv4 unless the socket is v6-only. procfs
	// does not expose that option, so report a potential conflict conservatively.
	if aa == netip.IPv6Unspecified() || ba == netip.IPv6Unspecified() {
		return true
	}
	return aa.Is4() == ba.Is4() && (aa.IsUnspecified() || ba.IsUnspecified())
}

func inspectPorts(r *Report, c lanconfig.Config, listeners func() ([]listener, error)) {
	operator, err1 := netip.ParseAddrPort(c.OperatorListen)
	agent, err2 := netip.ParseAddrPort(c.AgentListen)
	if err1 != nil || err2 != nil {
		r.add("listener_addresses", "fail", "Listener addresses could not be parsed.", "Select distinct canonical literal-IP listener addresses.")
		return
	}
	if overlapping(operator, agent) {
		r.add("listener_overlap", "fail", "The two configured listeners overlap on the same TCP port.", "Choose separate operator and agent ports before startup; no listener was opened.")
	}
	rows, err := listeners()
	if err != nil {
		r.add("port_snapshot", "unknown", "A complete bounded read-only Linux listener snapshot is unavailable.", "Inspect TCP listeners locally in the intended network namespace; do not treat this as a free-port result. Docker host publication needs a separate host-side inspection.")
		return
	}
	for _, target := range []struct {
		code    string
		address netip.AddrPort
	}{{"operator_port", operator}, {"agent_port", agent}} {
		conflict := false
		for _, row := range rows {
			conflict = conflict || overlapping(target.address, row.address)
		}
		if conflict {
			r.add(target.code, "fail", "The configured TCP address has an existing or possible dual-stack listener conflict.", "Identify the owning workload locally and review the chosen port/exposure. An already running manager can be the expected listener; doctor never stops or reconfigures it.")
		} else {
			r.add(target.code, "pass", "No conflicting TCP listener appeared in this read-only namespace snapshot; the port is not reserved.", "")
		}
	}
}
