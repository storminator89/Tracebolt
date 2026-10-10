package windowseventcontent

import (
	"context"
	"errors"
	"strconv"
	"unicode/utf16"
)

// Includes the terminating UTF-16 NUL. This caps each native allocation at
// 64 KiB, independent of the smaller UTF-8 output and aggregate byte budgets.
const maxNativeMessageUnits = 32 * 1024

var errInsufficientBuffer = errors.New("windows_event_content_internal_buffer_probe")

func selectionQuery(recordID uint64) string {
	return "*[System[EventRecordID=" + strconv.FormatUint(recordID, 10) + "]]"
}

type formatCall func([]uint16) (uint32, error)

// formatMessage never accepts partial text from a failing formatter or retries
// a growing allocation. The Win32 buffer sizes are UTF-16 characters, not bytes.
func formatMessage(ctx context.Context, call formatCall) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	used, err := call(nil)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !errors.Is(err, errInsufficientBuffer) {
		if err == nil {
			return "", ErrInvalidData
		}
		return "", safeError(err)
	}
	if used > maxNativeMessageUnits {
		return "", ErrBufferLimit
	}
	if used < 1 {
		return "", ErrInvalidData
	}
	buffer := make([]uint16, int(used))
	// A sentinel terminator prevents zero-initialized memory from making a
	// malformed native write look like a properly terminated message.
	for i := range buffer {
		buffer[i] = 0xffff
	}
	used, err = call(buffer)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	if errors.Is(err, errInsufficientBuffer) {
		return "", ErrBufferLimit
	}
	if err != nil {
		return "", safeError(err)
	}
	return decodeMessage(buffer, used)
}

func decodeMessage(buffer []uint16, used uint32) (string, error) {
	if len(buffer) > maxNativeMessageUnits || used < 1 || used > uint32(len(buffer)) || buffer[used-1] != 0 {
		return "", ErrInvalidData
	}
	units := buffer[:used-1]
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", ErrInvalidData
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", ErrInvalidData
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", ErrInvalidData
		}
	}
	return string(utf16.Decode(units)), nil
}
