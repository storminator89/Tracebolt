package windowssecurity

import (
	"encoding/binary"
	"errors"
	"runtime"
)

const maxActivationTokenBytes = 4096

var errActivationNoThreadToken = errors.New("no activation thread token")
var errActivationBufferSize = errors.New("activation token buffer required")

// activationTrustAPI is a package-private query/close seam. Production supplies
// fixed Windows APIs; portable tests exercise every failure without host reads.
type activationTrustAPI struct {
	openThread  func() (uintptr, error)
	openProcess func() (uintptr, error)
	query       func(uintptr, []byte) (uint32, error)
	close       func(uintptr) error
	bufferBase  func([]byte) uint64
}

func verifyActivationTrust(api activationTrustAPI, pointerBytes int) (err error) {
	if (pointerBytes != 4 && pointerBytes != 8) || api.openThread == nil || api.openProcess == nil || api.query == nil || api.close == nil || api.bufferBase == nil {
		return ErrDenied
	}
	thread, e := api.openThread()
	if e == nil {
		if thread != 0 {
			_ = api.close(thread)
		}
		return ErrDenied
	}
	if e != errActivationNoThreadToken || thread != 0 {
		return ErrDenied
	}
	process, e := api.openProcess()
	if e != nil || process == 0 {
		return ErrDenied
	}
	defer func() {
		if api.close(process) != nil {
			err = ErrDenied
		}
	}()
	needed, e := api.query(process, nil)
	if e != errActivationBufferSize || needed < uint32(2*pointerBytes+12) || needed > maxActivationTokenBytes {
		return ErrDenied
	}
	b := make([]byte, needed)
	returned, e := api.query(process, b)
	if e != nil || returned > uint32(len(b)) {
		return ErrDenied
	}
	trusted := trustedActivationIntegrity(b[:returned], api.bufferBase(b), pointerBytes)
	runtime.KeepAlive(b)
	if !trusted {
		return ErrDenied
	}
	return nil
}

// trustedActivationIntegrity parses a TOKEN_MANDATORY_LABEL captured in one
// bounded native query. Pointer fields are treated only as checked offsets into
// that same buffer; no address from the record is dereferenced. pointerBytes is
// supplied by the native adapter, and is explicit here for portable ABI fixtures.
func trustedActivationIntegrity(record []byte, base uint64, pointerBytes int) bool {
	if (pointerBytes != 4 && pointerBytes != 8) || base == 0 || len(record) > maxActivationTokenBytes {
		return false
	}
	headerBytes := 2 * pointerBytes // SID_AND_ATTRIBUTES includes x64 tail padding.
	if len(record) < headerBytes+12 {
		return false
	}
	var address uint64
	if pointerBytes == 4 {
		if base > 0xffffffff {
			return false
		}
		address = uint64(binary.LittleEndian.Uint32(record))
	} else {
		address = binary.LittleEndian.Uint64(record)
	}
	// SE_GROUP_INTEGRITY is mandatory; a deny-only label cannot establish trust.
	attributes := binary.LittleEndian.Uint32(record[pointerBytes:])
	if attributes&0x20 == 0 || attributes&0x10 != 0 || address < base || address%4 != 0 {
		return false
	}
	offset := address - base
	if offset < uint64(headerBytes) || offset > uint64(len(record)-12) {
		return false
	}
	sid := record[int(offset) : int(offset)+12]
	if sid[0] != 1 || sid[1] != 1 || sid[2] != 0 || sid[3] != 0 || sid[4] != 0 || sid[5] != 0 || sid[6] != 0 || sid[7] != 16 {
		return false
	}
	// Allow only the documented High and System labels. Medium Plus and unknown
	// future levels are deliberately rejected rather than inferred to be safe.
	rid := binary.LittleEndian.Uint32(sid[8:])
	return rid == 0x3000 || rid == 0x4000
}
