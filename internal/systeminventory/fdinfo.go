package systeminventory

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
)

const maxFDInfoHeaderBytes = 256

// parseSocketFDInfo is an UNWIRED pure parser for a possible later privileged
// source. No production path calls it. socketMount must eventually come from an
// independently verified socket in the same observation context; this function
// cannot establish that authority from an integer. An inode alone is not a
// socket identity because another filesystem can use the same inode number.
//
// Only the exact four mandatory header lines are consumed. There is deliberately
// no buffered read-ahead, suffix scan, raw metadata return or source-error text.
// Duplicate fields in this prefix fail; descriptor-specific suffixes (including
// anything resembling another header) are never inspected. Linux before 5.14
// can omit ino: a complete three-line prefix followed by EOF is unsupported.
func parseSocketFDInfo(ctx context.Context, r io.Reader, socketMount uint64) (uint64, bool, error) {
	if ctx == nil || r == nil || socketMount == 0 || socketMount > 1<<31-1 {
		return 0, false, ErrInvalidInput
	}
	fields := []string{"pos:", "flags:", "mnt_id:", "ino:"}
	consumed := 0
	var mount, inode uint64
	for index, field := range fields {
		line, err := readFDInfoHeaderLine(ctx, r, &consumed)
		if err != nil {
			if errors.Is(err, io.EOF) && index == 3 {
				return 0, false, SourceError{ReasonNotSupported}
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				err = ErrInvalidSource
			}
			return 0, false, err
		}
		key, value, ok := strings.Cut(line, "\t")
		if !ok || key != field || value == "" {
			return 0, false, ErrInvalidSource
		}
		switch index {
		case 0:
			// pos is signed kernel loff_t; no caller data or signs beyond '-' allowed.
			digits := strings.TrimPrefix(value, "-")
			if !decimalFDInfo(digits) || value == "-0" {
				return 0, false, ErrInvalidSource
			}
			if _, err := strconv.ParseInt(value, 10, 64); err != nil {
				return 0, false, ErrInvalidSource
			}
		case 1:
			for _, b := range value {
				if b < '0' || b > '7' {
					return 0, false, ErrInvalidSource
				}
			}
			if _, err := strconv.ParseUint(value, 8, 32); err != nil {
				return 0, false, ErrInvalidSource
			}
		case 2, 3:
			if !decimalFDInfo(value) {
				return 0, false, ErrInvalidSource
			}
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return 0, false, ErrInvalidSource
			}
			if index == 2 {
				if number == 0 || number > 1<<31-1 {
					return 0, false, ErrInvalidSource
				}
				mount = number
			} else {
				inode = number
			}
		}
	}
	if mount != socketMount || inode == 0 {
		return 0, false, nil
	}
	return inode, true, nil
}

func decimalFDInfo(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, b := range value {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func readFDInfoHeaderLine(ctx context.Context, r io.Reader, consumed *int) (string, error) {
	var line [maxFDInfoHeaderBytes]byte
	length := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if *consumed >= maxFDInfoHeaderBytes {
			return "", ErrSourceLimit
		}
		var one [1]byte
		n, err := r.Read(one[:])
		// A reader returning data with an error is failed conservatively. Do not
		// turn a truncated observation into a successful prefix.
		if err != nil {
			if errors.Is(err, io.EOF) && n == 0 {
				if length == 0 {
					return "", io.EOF
				}
				return "", io.ErrUnexpectedEOF
			}
			return "", SourceError{ReasonReadFailed}
		}
		if n != 1 {
			return "", SourceError{ReasonReadFailed}
		}
		*consumed++
		if one[0] == '\n' {
			return string(line[:length]), nil
		}
		line[length] = one[0]
		length++
	}
}
