package windowsupdateexecutor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
)

var (
	ErrToken         = errors.New("windows_update_executor_token_unproven")
	ErrImpersonation = errors.New("windows_update_executor_thread_impersonation_or_query_denied")
	ErrIntegrity     = errors.New("windows_update_executor_high_or_system_integrity_unproven")
	ErrAdministrator = errors.New("windows_update_executor_enabled_administrator_unproven")
	ErrRestricted    = errors.New("windows_update_executor_unrestricted_elevated_primary_token_unproven")
	errNoToken       = errors.New("no_thread_token")
	errBuffer        = errors.New("token_buffer_required")
)

const (
	tokenGroups       = 2
	tokenType         = 8
	tokenElevation    = 20
	tokenRestrictions = 21
	tokenIntegrity    = 25
)
const maxTokenBytes = 64 << 10

type tokenAPI struct {
	openThread  func() (uintptr, error)
	openProcess func() (uintptr, error)
	query       func(uintptr, uint32, []byte) (uint32, error)
	close       func(uintptr) error
	base        func([]byte) uint64
}

func verifyToken(api tokenAPI, width int) (err error) {
	if (width != 4 && width != 8) || api.openThread == nil || api.openProcess == nil || api.query == nil || api.close == nil || api.base == nil {
		return ErrToken
	}
	thread, e := api.openThread()
	if e != errNoToken || thread != 0 {
		if thread != 0 {
			_ = api.close(thread)
		}
		return ErrImpersonation
	}
	token, e := api.openProcess()
	if e != nil || token == 0 {
		if token != 0 {
			_ = api.close(token)
		}
		return ErrToken
	}
	defer func() {
		if api.close(token) != nil {
			err = ErrToken
		}
	}()
	scalar := func(class, want uint32) bool {
		b := make([]byte, 4)
		n, e := api.query(token, class, b)
		return e == nil && n == 4 && binary.LittleEndian.Uint32(b) == want
	}
	if !scalar(tokenType, 1) || !scalar(tokenElevation, 1) || !scalar(tokenRestrictions, 0) {
		return ErrRestricted
	}
	read := func(class uint32, check func([]byte, uint64, int) bool) bool {
		n, e := api.query(token, class, nil)
		if e != errBuffer || n == 0 || n > maxTokenBytes {
			return false
		}
		b := make([]byte, n)
		used, e := api.query(token, class, b)
		if e != nil || used == 0 || used > n {
			return false
		}
		valid := check(b[:used], api.base(b), width)
		runtime.KeepAlive(b)
		return valid
	}
	if !read(tokenIntegrity, highIntegrity) {
		return ErrIntegrity
	}
	if !read(tokenGroups, enabledAdministrator) {
		return ErrAdministrator
	}
	return nil
}
func sidOffset(record []byte, at int, base uint64, width, minimum, length int) (int, bool) {
	if base == 0 || (width != 4 && width != 8) || at < 0 || at > len(record)-width || length > len(record) {
		return 0, false
	}
	var address uint64
	if width == 4 {
		if base > 0xffffffff {
			return 0, false
		}
		address = uint64(binary.LittleEndian.Uint32(record[at:]))
	} else {
		address = binary.LittleEndian.Uint64(record[at:])
	}
	if address < base || address%4 != 0 {
		return 0, false
	}
	offset := address - base
	if offset < uint64(minimum) || offset > uint64(len(record)-length) {
		return 0, false
	}
	return int(offset), true
}
func highIntegrity(b []byte, base uint64, width int) bool {
	if (width != 4 && width != 8) || len(b) < 2*width+12 || len(b) > maxTokenBytes {
		return false
	}
	attributes := binary.LittleEndian.Uint32(b[width:])
	if attributes&0x20 == 0 || attributes&0x10 != 0 {
		return false
	}
	off, ok := sidOffset(b, 0, base, width, 2*width, 12)
	if !ok {
		return false
	}
	sid := b[off : off+12]
	if !bytes.Equal(sid[:8], []byte{1, 1, 0, 0, 0, 0, 0, 16}) {
		return false
	}
	rid := binary.LittleEndian.Uint32(sid[8:])
	return rid == 0x3000 || rid == 0x4000
}
func enabledAdministrator(b []byte, base uint64, width int) bool {
	if (width != 4 && width != 8) || len(b) < width || len(b) > maxTokenBytes {
		return false
	}
	count := uint64(binary.LittleEndian.Uint32(b))
	end := uint64(width) + count*uint64(2*width)
	if count == 0 || end > uint64(len(b)) {
		return false
	}
	found := false
	for i := uint64(0); i < count; i++ {
		at := width + int(i)*2*width
		off, ok := sidOffset(b, at, base, width, int(end), 8)
		if !ok {
			return false
		}
		sid := b[off:]
		if sid[0] != 1 || sid[1] > 15 || len(sid) < 8+4*int(sid[1]) {
			return false
		}
		// S-1-5-32-544, BUILTIN\\Administrators. Mere presence/deny-only is insufficient.
		if sid[1] == 2 && bytes.Equal(sid[:8], []byte{1, 2, 0, 0, 0, 0, 0, 5}) && binary.LittleEndian.Uint32(sid[8:]) == 32 && binary.LittleEndian.Uint32(sid[12:]) == 544 {
			attributes := binary.LittleEndian.Uint32(b[at+width:])
			if found || attributes&4 == 0 || attributes&0x10 != 0 {
				return false
			}
			found = true
		}
	}
	return found
}
