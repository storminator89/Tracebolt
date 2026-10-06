package systeminventory

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const socketFDInfo = "pos:\t0\nflags:\t02000002\nmnt_id:\t9\nino:\t123\n"

func TestSocketFDInfoExactMountAndInode(t *testing.T) {
	for _, tc := range []struct {
		name, raw    string
		mount, inode uint64
		match        bool
	}{
		{"socket", socketFDInfo, 9, 123, true},
		{"same inode different filesystem", strings.Replace(socketFDInfo, "mnt_id:\t9", "mnt_id:\t10", 1), 9, 0, false},
		{"another socket inode", strings.Replace(socketFDInfo, "ino:\t123", "ino:\t124", 1), 9, 124, true},
		{"zero inode", strings.Replace(socketFDInfo, "ino:\t123", "ino:\t0", 1), 9, 0, false},
		{"irrelevant metadata", socketFDInfo + "private-fixture-field:\tDO_NOT_RETAIN_THIS\n", 9, 123, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inode, match, err := parseSocketFDInfo(context.Background(), strings.NewReader(tc.raw), tc.mount)
			if err != nil || inode != tc.inode || match != tc.match {
				t.Fatalf("inode=%d match=%v err=%v", inode, match, err)
			}
		})
	}
}

func TestSocketFDInfoRejectsMalformedOrDuplicateHeaders(t *testing.T) {
	for _, raw := range []string{
		"", "ino:\t123\n", strings.Replace(socketFDInfo, "pos:\t0\n", "", 1),
		strings.Replace(socketFDInfo, "pos:\t0", "pos:\t+0", 1),
		strings.Replace(socketFDInfo, "flags:\t02000002", "flags:\t8", 1),
		strings.Replace(socketFDInfo, "mnt_id:\t9", "mnt_id:\t0", 1),
		strings.Replace(socketFDInfo, "mnt_id:\t9", "mnt_id:\t+9", 1),
		strings.Replace(socketFDInfo, "ino:\t123", "ino:\t-1", 1),
		strings.Replace(socketFDInfo, "ino:\t123", "ino:\t18446744073709551616", 1),
		strings.Replace(socketFDInfo, "ino:\t123", "ino:\t123 extra", 1),
		strings.Replace(socketFDInfo, "ino:\t123", "ino:\t123\x00", 1),
		strings.Replace(socketFDInfo, "ino:\t123\n", "ino:\t123", 1),
		strings.Replace(socketFDInfo, "mnt_id:\t9", "flags:\t9", 1),
		"pos:\t0\npos:\t0\nmnt_id:\t9\nino:\t123\n",
		"pos:\t0\nflags:\t02\nmnt_id:\t9\nmnt_id:\t9\n",
		"private:\tDO_NOT_RETAIN_THIS\n" + socketFDInfo,
	} {
		inode, match, err := parseSocketFDInfo(context.Background(), strings.NewReader(raw), 9)
		if !errors.Is(err, ErrInvalidSource) || inode != 0 || match {
			t.Fatalf("malformed data accepted: inode=%d match=%v err=%v", inode, match, err)
		}
		if strings.Contains(err.Error(), "DO_NOT_RETAIN_THIS") {
			t.Fatal("raw metadata in error")
		}
	}
}

func TestSocketFDInfoUnsupportedShapeAndBounds(t *testing.T) {
	old := "pos:\t0\nflags:\t02\nmnt_id:\t9\n"
	for _, raw := range []string{old} {
		_, _, err := parseSocketFDInfo(context.Background(), strings.NewReader(raw), 9)
		var source SourceError
		if !errors.As(err, &source) || source.Reason != ReasonNotSupported {
			t.Fatalf("old shape: %v", err)
		}
	}
	for _, raw := range []string{"pos:\t" + strings.Repeat("1", maxFDInfoHeaderBytes) + "\n", "pos:\t0\nflags:\t02\nmnt_id:\t" + strings.Repeat("1", maxFDInfoHeaderBytes) + "\n"} {
		inode, match, err := parseSocketFDInfo(context.Background(), strings.NewReader(raw), 9)
		if !errors.Is(err, ErrSourceLimit) || inode != 0 || match {
			t.Fatalf("limit: inode=%d match=%v err=%v", inode, match, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := parseSocketFDInfo(ctx, strings.NewReader(socketFDInfo), 9); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, mount := range []uint64{0, 1 << 63} {
		if _, _, err := parseSocketFDInfo(context.Background(), strings.NewReader(socketFDInfo), mount); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	if _, _, err := parseSocketFDInfo(nil, strings.NewReader(socketFDInfo), 9); !errors.Is(err, ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, _, err := parseSocketFDInfo(context.Background(), nil, 9); !errors.Is(err, ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, _, err := parseSocketFDInfo(context.Background(), io.MultiReader(strings.NewReader("pos:\t0\n"), failingFDInfoReader{}), 9); err == nil {
		t.Fatal("read failure admitted")
	}
}

type failingFDInfoReader struct{}

func (failingFDInfoReader) Read([]byte) (int, error) { return 0, errors.New("inert source error") }

func TestSocketFDInfoNeverReadsDescriptorMetadata(t *testing.T) {
	r := &prefixOnlyFDInfoReader{prefix: []byte(socketFDInfo)}
	inode, match, err := parseSocketFDInfo(context.Background(), r, 9)
	if err != nil || inode != 123 || !match || len(r.prefix) != 0 {
		t.Fatalf("inode=%d match=%v err=%v", inode, match, err)
	}
}

type prefixOnlyFDInfoReader struct{ prefix []byte }

func (r *prefixOnlyFDInfoReader) Read(dst []byte) (int, error) {
	if len(r.prefix) == 0 || len(dst) != 1 {
		panic("parser read outside exact header prefix")
	}
	dst[0] = r.prefix[0]
	r.prefix = r.prefix[1:]
	return 1, nil
}

func TestSocketFDInfoPartialReadErrorAndMidHeaderCancellation(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("PRIVATE_FDINFO_SOURCE")} {
		inode, match, got := parseSocketFDInfo(context.Background(), partialErrorFDInfoReader{err}, 9)
		if inode != 0 || match || got == nil || strings.Contains(got.Error(), "PRIVATE_FDINFO_SOURCE") {
			t.Fatalf("partial error inode=%d match=%v err=%v", inode, match, got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	inode, match, err := parseSocketFDInfo(ctx, cancelFDInfoReader{cancel}, 9)
	if inode != 0 || match || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}

type partialErrorFDInfoReader struct{ err error }

func (r partialErrorFDInfoReader) Read(p []byte) (int, error) { p[0] = 'p'; return 1, r.err }

type cancelFDInfoReader struct{ cancel context.CancelFunc }

func (r cancelFDInfoReader) Read(p []byte) (int, error) { p[0] = 'p'; r.cancel(); return 1, nil }
