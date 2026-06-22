package hopper

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The member every fixture in this file carries, and the path callers request.
// Requesting "hello.txt" (not "payload/hello.txt") also exercises the one-level
// prefix strip in archivePathMatches that real npm/pypi/go layouts need.
const (
	memberDir     = "payload/hello.txt"
	memberRequest = "hello.txt"
	memberBody    = "hello from the archive\n"
)

//go:embed testdata/member.7z
var fixture7z []byte

//go:embed testdata/member.tar.bz2
var fixtureTarBz2 []byte

// member-enc.7z is header-encrypted (7z -mhe=on) with password "infected".
//
//go:embed testdata/member-enc.7z
var fixture7zEnc []byte

// member-badpw.7z is header-encrypted with a password NOT in sevenZPasswords.
//
//go:embed testdata/member-badpw.7z
var fixture7zBadPw []byte

// assertMember streams request out of an in-memory archive and checks that the
// bytes equal memberBody, that setLen reported the exact length once, and that
// no error occurred.
func assertMember(t *testing.T, archive []byte, fileType, request string) {
	t.Helper()
	var out bytes.Buffer
	calls, gotLen := 0, int64(-1)
	err := StreamArchiveMember(bytes.NewReader(archive), int64(len(archive)), fileType, request, 1<<20,
		func(n int64) { calls++; gotLen = n }, &out)
	if err != nil {
		t.Fatalf("%s: StreamArchiveMember(%q): %v", fileType, request, err)
	}
	if calls != 1 {
		t.Errorf("%s: setLen called %d times, want 1", fileType, calls)
	}
	if gotLen != int64(len(memberBody)) {
		t.Errorf("%s: setLen size = %d, want %d", fileType, gotLen, len(memberBody))
	}
	if out.String() != memberBody {
		t.Errorf("%s: body = %q, want %q", fileType, out.String(), memberBody)
	}
}

// makeTar builds an uncompressed tar holding a single file with memberBody.
func makeTar(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(memberBody)), Mode: 0o644}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write([]byte(memberBody)); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func xzBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	xw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatalf("xz writer: %v", err)
	}
	if _, err := xw.Write(data); err != nil {
		t.Fatalf("xz write: %v", err)
	}
	if err := xw.Close(); err != nil {
		t.Fatalf("xz close: %v", err)
	}
	return buf.Bytes()
}

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// makeZip builds a zip holding the given name→body entries (deflated).
func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %q: %v", name, err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestExtractCompressedTars covers the tar-based families that differ only in
// their outer compression: a member must come out identically from each.
func TestExtractCompressedTars(t *testing.T) {
	tarBytes := makeTar(t, memberDir)
	cases := []struct {
		fileType string
		archive  []byte
	}{
		{"tar", tarBytes},
		{"tar.gz", gzipBytes(t, tarBytes)},
		{"tgz", gzipBytes(t, tarBytes)},
		{"crate", gzipBytes(t, tarBytes)},
		{"tar.xz", xzBytes(t, tarBytes)},
		{"tar.zst", zstdBytes(t, tarBytes)},
		{"tar.bz2", fixtureTarBz2},
	}
	for _, tc := range cases {
		t.Run(tc.fileType, func(t *testing.T) {
			assertMember(t, tc.archive, tc.fileType, memberRequest)
		})
	}
}

// TestExtractZipFamily covers the zip-equivalent container types — cleave tags
// the same on-the-wire zip format with many ecosystem-specific names.
func TestExtractZipFamily(t *testing.T) {
	z := makeZip(t, map[string][]byte{memberDir: []byte(memberBody)})
	for _, ft := range []string{"zip", "jar", "whl", "nupkg", "xpi", "vsix", "apk_android", "aab", "ipa", "war", "ear"} {
		t.Run(ft, func(t *testing.T) {
			assertMember(t, z, ft, memberRequest)
		})
	}
}

// TestExtractCrx strips the Chrome-extension crx3 wrapper and reads the zip
// member behind it.
func TestExtractCrx(t *testing.T) {
	z := makeZip(t, map[string][]byte{memberDir: []byte(memberBody)})
	var buf bytes.Buffer
	var u32 [4]byte
	buf.WriteString("Cr24")
	binary.LittleEndian.PutUint32(u32[:], 3) // crx3
	buf.Write(u32[:])
	header := []byte("crx3-signed-header-bytes")
	binary.LittleEndian.PutUint32(u32[:], uint32(len(header)))
	buf.Write(u32[:])
	buf.Write(header)
	buf.Write(z)
	assertMember(t, buf.Bytes(), "crx", memberRequest)
}

// TestExtract7z reads a member from a real 7z fixture (no Go 7z writer exists).
func TestExtract7z(t *testing.T) {
	assertMember(t, fixture7z, "7z", memberRequest)
}

// TestExtract7zEncrypted reads a member from a header-encrypted 7z, exercising
// the malware-sample password fallback (the fixture's password is "infected").
func TestExtract7zEncrypted(t *testing.T) {
	assertMember(t, fixture7zEnc, "7z", memberRequest)
}

// TestExtract7zUndecryptable confirms that a 7z whose password is not in the
// list surfaces ErrArchiveEncrypted (mapped to 422), not a generic failure.
func TestExtract7zUndecryptable(t *testing.T) {
	err := StreamArchiveMember(bytes.NewReader(fixture7zBadPw), int64(len(fixture7zBadPw)),
		"7z", memberRequest, 1<<20, func(int64) {}, io.Discard)
	if !errors.Is(err, ErrArchiveEncrypted) {
		t.Fatalf("got %v, want ErrArchiveEncrypted", err)
	}
}

// makeCpioNewc builds a newc-format cpio holding one file plus the TRAILER.
func makeCpioNewc(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writeEntry := func(name string, body []byte) {
		nameZ := append([]byte(name), 0)
		// 6-byte magic + 13 eight-hex fields; order: ino, mode, uid, gid,
		// nlink, mtime, filesize, devmajor, devminor, rdevmajor, rdevminor,
		// namesize, check.
		fmt.Fprintf(&buf, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			0, 0o100644, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(nameZ), 0)
		buf.Write(nameZ)
		buf.Write(make([]byte, (4-(110+len(nameZ))%4)%4))
		buf.Write(body)
		buf.Write(make([]byte, (4-len(body)%4)%4))
	}
	writeEntry("."+"/"+name, []byte(body)) // rpm cpio names are "./"-prefixed
	writeEntry("TRAILER!!!", nil)
	return buf.Bytes()
}

// makeRpm wraps a gzip-compressed cpio payload in a minimal but structurally
// valid rpm (lead + empty signature header + empty main header).
func makeRpm(t *testing.T, payload []byte) []byte {
	t.Helper()
	lead := make([]byte, 96)
	lead[0], lead[1], lead[2], lead[3] = 0xed, 0xab, 0xee, 0xdb
	emptyHeader := func() []byte {
		h := make([]byte, 16)
		h[0], h[1], h[2], h[3] = 0x8e, 0xad, 0xe8, 0x01 // magic + version; nindex=hsize=0
		return h
	}
	buf := make([]byte, 0, 128+len(payload))
	buf = append(buf, lead...)
	buf = append(buf, emptyHeader()...) // signature header (already 8-aligned at offset 112)
	buf = append(buf, emptyHeader()...) // main header
	return append(buf, payload...)
}

// TestExtractRpm reads a member out of an rpm's compressed cpio payload.
func TestExtractRpm(t *testing.T) {
	cpio := makeCpioNewc(t, memberDir, memberBody)
	rpm := makeRpm(t, gzipBytes(t, cpio))
	assertMember(t, rpm, "rpm", memberRequest)
}

// makeDeb builds a deb (ar archive) whose data member is the given tarball under
// the given name (e.g. data.tar.gz).
func makeDeb(t *testing.T, dataName string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	writeAr := func(name string, body []byte) {
		// 60-byte header: name[16] mtime[12] uid[6] gid[6] mode[8] size[10] magic[2].
		hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(body))
		if len(hdr) != 60 {
			t.Fatalf("ar header for %q is %d bytes, want 60", name, len(hdr))
		}
		buf.WriteString(hdr)
		buf.Write(body)
		if len(body)%2 == 1 {
			buf.WriteByte('\n') // entries align to an even offset
		}
	}
	writeAr("debian-binary", []byte("2.0\n"))
	writeAr(dataName, data)
	return buf.Bytes()
}

// TestExtractDeb reads a member from the data.tar.* inside a deb, across the
// compressions Debian actually ships.
func TestExtractDeb(t *testing.T) {
	tarBytes := makeTar(t, memberDir)
	cases := []struct {
		name string
		data []byte
	}{
		{"data.tar", tarBytes},
		{"data.tar.gz", gzipBytes(t, tarBytes)},
		{"data.tar.xz", xzBytes(t, tarBytes)},
		{"data.tar.zst", zstdBytes(t, tarBytes)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertMember(t, makeDeb(t, tc.name, tc.data), "deb", memberRequest)
		})
	}
}

// TestExtractDebDataPrefix locks in the deb path fix: cleave records deb members
// under the ar member stem ("data/usr/bin/tool"), which must be stripped to match
// the data.tar's own entries.
func TestExtractDebDataPrefix(t *testing.T) {
	data := gzipBytes(t, makeTar(t, "usr/bin/tool"))
	deb := makeDeb(t, "data.tar.gz", data)
	assertMember(t, deb, "deb", "data/usr/bin/tool")
}

// TestExtractNestedConda is the regression for the real "zip 404": a .conda is a
// zip whose member is itself a .tar.zst holding the leaf. The chain is written
// `inner.tar.zst!leaf`, and extraction must descend both levels.
func TestExtractNestedConda(t *testing.T) {
	innerTarZst := zstdBytes(t, makeTar(t, memberDir))
	conda := makeZip(t, map[string][]byte{"pkg-libgit2-1.9.3.tar.zst": innerTarZst})

	// Full inner path and the one-level-stripped form must both resolve.
	assertMember(t, conda, "conda", "pkg-libgit2-1.9.3.tar.zst!"+memberDir)
	assertMember(t, conda, "conda", "pkg-libgit2-1.9.3.tar.zst!"+memberRequest)
}

// TestExtractNestedZipInZip exercises a second-level zip reached through an
// outer zip, confirming the recursion is container-agnostic.
func TestExtractNestedZipInZip(t *testing.T) {
	inner := makeZip(t, map[string][]byte{memberDir: []byte(memberBody)})
	outer := makeZip(t, map[string][]byte{"inner.zip": inner})
	assertMember(t, outer, "zip", "inner.zip!"+memberRequest)
}

// TestExtractMissingAndUnsupported confirms the typed sentinels still surface so
// the HTTP layer maps them to 404 / 415.
func TestExtractMissingAndUnsupported(t *testing.T) {
	z := makeZip(t, map[string][]byte{memberDir: []byte(memberBody)})
	var out bytes.Buffer
	noLen := func(int64) {}
	if err := StreamArchiveMember(bytes.NewReader(z), int64(len(z)), "zip", "nope.txt", 1<<20, noLen, &out); err == nil {
		t.Error("missing member: expected error")
	}
	if err := StreamArchiveMember(bytes.NewReader([]byte("xx")), 2, "rar", "x", 1<<20, noLen, &out); err == nil {
		t.Error("rar: expected unsupported error")
	}
}
