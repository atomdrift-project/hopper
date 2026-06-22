package hopper

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// IsCorruptArchive reports whether err means the archive bytes themselves are
// malformed — a bad header, checksum mismatch, or truncated/garbage compressed
// stream — as opposed to a server-side I/O fault or a client disconnect. The
// data is the caller's problem, so the HTTP layer maps these to 422 rather than
// 500. Covers the standard-library container/codec errors (tar, zip, gzip,
// flate, bzip2); exotic codec corruption (zstd/xz/7z) falls through to 500.
func IsCorruptArchive(err error) bool {
	if errors.Is(err, tar.ErrHeader) ||
		errors.Is(err, zip.ErrFormat) || errors.Is(err, zip.ErrChecksum) || errors.Is(err, zip.ErrAlgorithm) ||
		errors.Is(err, gzip.ErrHeader) || errors.Is(err, gzip.ErrChecksum) {
		return true
	}
	var (
		flateCorrupt  flate.CorruptInputError
		flateInternal flate.InternalError
		bz2Err        bzip2.StructuralError
	)
	return errors.As(err, &flateCorrupt) || errors.As(err, &flateInternal) || errors.As(err, &bz2Err)
}

// maxNestedArchiveBytes bounds an *intermediate* nested archive that must be
// extracted to reach a deeper member (e.g. the pkg-*.tar.zst inside a .conda).
// The final leaf is still capped by the caller's maxBytes; this only limits how
// large an inner container we'll spool to a temp file before descending.
const maxNestedArchiveBytes = 2 << 30 // 2 GiB

// NestedSpoolDir is the directory streamNestedMember spools intermediate
// archives into. An empty value falls back to os.TempDir() (i.e. $TMPDIR or
// /tmp), which under systemd's PrivateTmp is frequently a tmpfs (RAM-backed) —
// spooling a multi-GB inner container there would defeat the point of
// streaming. main sets this to an on-disk path under the data root before the
// server starts serving; it is only read afterwards, so no synchronisation is
// needed.
var NestedSpoolDir string

// StreamArchiveMember writes the single member innerPath out of an archive to w
// without ever holding the whole archive in memory. src provides random access
// over the archive (size is its length in bytes).
//
// It supports the container types cleave records as archive parents: tar and
// its compressed variants (tar.gz/tgz, tar.xz, tar.zst, tar.bz2), the zip
// family (jar, war, ear, whl, egg, nupkg, xpi, vsix, apk_android, aab, ipa,
// conda, …), Chrome's crx wrapper, 7z, rpm (cpio payload) and deb (ar →
// data.tar.*). Unsupported types return an "unsupported archive: <type>" error
// that the HTTP layer maps to 415.
//
// innerPath may descend through more than one archive — a .conda (zip) whose
// member is itself a .tar.zst holding the leaf — written by cleave as
// `outer!!inner.tar.zst!leaf`. Such chains are peeled one level at a time: the
// inner archive is spooled to a temp file and the function recurses.
//
// When src is an *os.File and a zip member is stored uncompressed, the member is
// copied as a raw file region so io.Copy to a TCP socket uses sendfile(2).
// Compressed members stream through a bounded decompressor.
//
// setLen is called exactly once with the leaf's exact size immediately before
// the first byte is written, letting an HTTP caller set Content-Length. On any
// pre-write error (member missing, too large, unsupported type) it is never
// called, so the caller can still choose a status code.
func StreamArchiveMember(src io.ReaderAt, size int64, fileType, innerPath string, maxBytes int64, setLen func(int64), w io.Writer) error {
	if head, tail, nested := splitArchiveChain(innerPath); nested {
		return streamNestedMember(src, size, fileType, head, tail, maxBytes, setLen, w)
	}
	return streamArchiveLeaf(src, size, fileType, innerPath, maxBytes, setLen, w)
}

// streamArchiveLeaf extracts a member that lives directly inside this archive
// (no further nesting), dispatching on the container type.
func streamArchiveLeaf(src io.ReaderAt, size int64, fileType, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	switch strings.ToLower(strings.TrimSpace(fileType)) {
	case "tar":
		return streamTarMember(io.NewSectionReader(src, 0, size), member, maxBytes, setLen, w)
	case "tar.gz", "tgz", "gz", "crate":
		return streamCompressedTar(src, size, "gz", member, maxBytes, setLen, w)
	case "tar.xz", "txz", "xz":
		return streamCompressedTar(src, size, "xz", member, maxBytes, setLen, w)
	case "tar.zst", "tzst", "zst":
		return streamCompressedTar(src, size, "zst", member, maxBytes, setLen, w)
	case "tar.bz2", "tbz2", "tbz", "bz2":
		return streamCompressedTar(src, size, "bz2", member, maxBytes, setLen, w)
	case "zip", "jar", "war", "ear", "apk", "apk_android", "aab", "ipa",
		"whl", "egg", "gem", "nupkg", "xpi", "vsix", "conda":
		return streamZipMember(src, size, member, maxBytes, setLen, w)
	case "crx":
		return streamCrxMember(src, size, member, maxBytes, setLen, w)
	case "7z":
		return stream7zMember(src, size, member, maxBytes, setLen, w)
	case "rpm":
		return streamRpmMember(src, size, member, maxBytes, setLen, w)
	case "deb", "ipk":
		return streamDebMember(src, size, member, maxBytes, setLen, w)
	}
	return fmt.Errorf("%w: %s", ErrUnsupportedArchive, fileType)
}

// streamNestedMember spools the intermediate archive named by head to a temp
// file, then recurses to extract tail from it. The temp file gives the inner
// container random access (zip needs it) and keeps memory bounded to the
// decompressor's working set — the inner archive lands on disk, never in RAM.
func streamNestedMember(src io.ReaderAt, size int64, fileType, head, tail string, maxBytes int64, setLen func(int64), w io.Writer) error {
	nestedType := archiveTypeFromName(head)
	if nestedType == "" {
		return fmt.Errorf("%w: nested %s", ErrUnsupportedArchive, head)
	}

	tmp, err := os.CreateTemp(NestedSpoolDir, "hopper-nested-*")
	if err != nil {
		return fmt.Errorf("nested temp: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
	defer tmp.Close()           //nolint:errcheck // closed again is harmless

	// Extract the inner archive with a no-op setLen — it is not the leaf.
	if err := streamArchiveLeaf(src, size, fileType, head, maxNestedArchiveBytes, func(int64) {}, tmp); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("nested seek: %w", err)
	}
	st, err := tmp.Stat()
	if err != nil {
		return fmt.Errorf("nested stat: %w", err)
	}
	return StreamArchiveMember(tmp, st.Size(), nestedType, tail, maxBytes, setLen, w)
}

// splitArchiveChain peels the first nested-archive boundary out of an inner
// path. cleave joins nested members with "!" (the outer "!!" is stripped by
// PathInsideArchive before we get here). head names a member of the current
// archive that is itself an archive; tail is the path within it. A "!" is only
// treated as a boundary when the segment to its left is a recognised archive,
// so a stray "!" in an ordinary filename is left alone.
func splitArchiveChain(p string) (head, tail string, nested bool) {
	for i := range len(p) {
		if p[i] != '!' {
			continue
		}
		if archiveTypeFromName(p[:i]) == "" {
			continue
		}
		j := i
		for j < len(p) && p[j] == '!' {
			j++
		}
		if j >= len(p) { // trailing '!', not a real boundary
			continue
		}
		return p[:i], p[j:], true
	}
	return p, "", false
}

// archiveTypeFromName infers a container type from a member's filename, used to
// type the intermediate archives in a nested chain. Returns "" when the name is
// not a recognised archive.
func archiveTypeFromName(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"), strings.HasSuffix(n, ".crate"):
		return "tar.gz"
	case strings.HasSuffix(n, ".tar.xz"), strings.HasSuffix(n, ".txz"):
		return "tar.xz"
	case strings.HasSuffix(n, ".tar.zst"), strings.HasSuffix(n, ".tzst"):
		return "tar.zst"
	case strings.HasSuffix(n, ".tar.bz2"), strings.HasSuffix(n, ".tbz2"), strings.HasSuffix(n, ".tbz"):
		return "tar.bz2"
	case strings.HasSuffix(n, ".tar"):
		return "tar"
	case strings.HasSuffix(n, ".conda"):
		return "zip"
	case strings.HasSuffix(n, ".zip"), strings.HasSuffix(n, ".jar"), strings.HasSuffix(n, ".war"),
		strings.HasSuffix(n, ".ear"), strings.HasSuffix(n, ".whl"), strings.HasSuffix(n, ".egg"),
		strings.HasSuffix(n, ".nupkg"), strings.HasSuffix(n, ".xpi"), strings.HasSuffix(n, ".vsix"),
		strings.HasSuffix(n, ".apk"), strings.HasSuffix(n, ".aab"), strings.HasSuffix(n, ".ipa"):
		return "zip"
	case strings.HasSuffix(n, ".crx"):
		return "crx"
	case strings.HasSuffix(n, ".7z"):
		return "7z"
	case strings.HasSuffix(n, ".rpm"):
		return "rpm"
	case strings.HasSuffix(n, ".deb"), strings.HasSuffix(n, ".ipk"):
		return "deb"
	case strings.HasSuffix(n, ".gz"):
		return "tar.gz"
	case strings.HasSuffix(n, ".xz"):
		return "tar.xz"
	case strings.HasSuffix(n, ".zst"):
		return "tar.zst"
	case strings.HasSuffix(n, ".bz2"):
		return "tar.bz2"
	}
	return ""
}

// streamCompressedTar decompresses src with comp and streams the named tar
// member out, never buffering more than the decompressor's working set.
func streamCompressedTar(src io.ReaderAt, size int64, comp, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	dr, closeFn, err := newDecompressor(comp, io.NewSectionReader(src, 0, size))
	if err != nil {
		return err
	}
	defer closeFn()
	return streamTarMember(dr, member, maxBytes, setLen, w)
}

// newDecompressor wraps r in a streaming decompressor for comp. The returned
// closeFn releases the decompressor's resources and must always be called.
func newDecompressor(comp string, r io.Reader) (io.Reader, func(), error) {
	switch comp {
	case "gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("gunzip: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil //nolint:errcheck // read-only stream
	case "xz":
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("xz: %w", err)
		}
		return xr, func() {}, nil
	case "lzma":
		lr, err := lzma.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("lzma: %w", err)
		}
		return lr, func() {}, nil
	case "zst":
		zr, err := zstd.NewReader(r, zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, nil, fmt.Errorf("zstd: %w", err)
		}
		return zr, zr.Close, nil
	case "bz2":
		return bzip2.NewReader(r), func() {}, nil
	}
	return nil, nil, fmt.Errorf("%w: compression %s", ErrUnsupportedArchive, comp)
}

// streamCrxMember strips the Chrome extension (crx) wrapper — a small header in
// front of an ordinary zip — and streams the requested zip member. Supports
// crx2 and crx3 headers.
func streamCrxMember(src io.ReaderAt, size int64, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	var hdr [12]byte
	if _, err := src.ReadAt(hdr[:], 0); err != nil {
		return fmt.Errorf("crx header: %w", err)
	}
	if string(hdr[:4]) != "Cr24" {
		return errors.New("crx: bad magic")
	}
	var zipOff int64
	switch version := binary.LittleEndian.Uint32(hdr[4:8]); version {
	case 2:
		pubKeyLen := int64(binary.LittleEndian.Uint32(hdr[8:12]))
		var sig [4]byte
		if _, err := src.ReadAt(sig[:], 12); err != nil {
			return fmt.Errorf("crx2 siglen: %w", err)
		}
		zipOff = 16 + pubKeyLen + int64(binary.LittleEndian.Uint32(sig[:]))
	case 3:
		zipOff = 12 + int64(binary.LittleEndian.Uint32(hdr[8:12]))
	default:
		return fmt.Errorf("crx: unsupported version %d", version)
	}
	if zipOff <= 0 || zipOff >= size {
		return fmt.Errorf("crx: zip offset %d out of range", zipOff)
	}
	return streamZipMember(io.NewSectionReader(src, zipOff, size-zipOff), size-zipOff, member, maxBytes, setLen, w)
}

// sevenZPasswords are tried in order when opening a 7z: "" first for the common
// unencrypted case, then the malware-sample passwords (kept in sync with
// cleave's DEFAULT_ZIP_PASSWORDS). Encrypted 7z malware samples are near-
// universally one of these.
var sevenZPasswords = []string{"", "infected", "infect3d", "malware", "virus", "password", "virussign"}

// stream7zMember extracts a member from a 7z, trying the known passwords for
// encrypted archives. The member is decoded to a temp file first: a wrong
// password only fails partway through (a decode/CRC error), so decoding to the
// side keeps corrupt bytes from ever reaching w. The validated member is then
// copied out.
func stream7zMember(src io.ReaderAt, size int64, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	tmp, err := os.CreateTemp("", "hopper-7z-*")
	if err != nil {
		return fmt.Errorf("7z temp: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // best-effort cleanup
	defer tmp.Close()           //nolint:errcheck // closed again is harmless

	n, err := extract7zMember(src, size, member, maxBytes, tmp)
	if err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("7z temp seek: %w", err)
	}
	setLen(n)
	if _, err := io.Copy(w, tmp); err != nil {
		return fmt.Errorf("7z stream: %w", err)
	}
	return nil
}

// extract7zMember decodes member into out, trying each candidate password until
// one decodes cleanly. out is rewound and truncated before each attempt so a
// failed decode leaves no residue.
func extract7zMember(src io.ReaderAt, size int64, member string, maxBytes int64, out *os.File) (int64, error) {
	var lastErr error
	for _, pw := range sevenZPasswords {
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			return 0, fmt.Errorf("7z temp seek: %w", err)
		}
		if err := out.Truncate(0); err != nil {
			return 0, fmt.Errorf("7z temp truncate: %w", err)
		}
		n, err := try7zPassword(src, size, member, maxBytes, pw, out)
		switch {
		case err == nil:
			return n, nil
		case errors.Is(err, ErrArchiveMemberNotFound), errors.Is(err, ErrArchiveMemberTooLarge):
			return 0, err // the archive opened; a password won't change the listing or size
		default:
			lastErr = err
		}
	}
	return 0, fmt.Errorf("%w: 7z, tried %d passwords: %w", ErrArchiveEncrypted, len(sevenZPasswords)-1, lastErr)
}

// try7zPassword opens the 7z with pw ("" for none) and copies member to out.
func try7zPassword(src io.ReaderAt, size int64, member string, maxBytes int64, pw string, out io.Writer) (int64, error) {
	var (
		zr  *sevenzip.Reader
		err error
	)
	if pw == "" {
		zr, err = sevenzip.NewReader(src, size)
	} else {
		zr, err = sevenzip.NewReaderWithPassword(src, size, pw)
	}
	if err != nil {
		return 0, err
	}
	for _, f := range zr.File {
		if !archivePathMatches(f.Name, member) {
			continue
		}
		n := f.FileInfo().Size()
		if maxBytes >= 0 && n > maxBytes {
			return 0, fmt.Errorf("%w (>%d bytes)", ErrArchiveMemberTooLarge, maxBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return 0, err
		}
		written, cerr := io.Copy(out, io.LimitReader(rc, n))
		_ = rc.Close() //nolint:errcheck // read-only stream
		if cerr != nil {
			return 0, cerr // a wrong password surfaces here as a decode/CRC error
		}
		return written, nil
	}
	return 0, fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, member)
}

// streamRpmMember skips the rpm lead and headers to the compressed cpio payload,
// detects the payload compression by magic, and streams the requested member
// out of the cpio.
func streamRpmMember(src io.ReaderAt, size int64, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	off, err := rpmPayloadOffset(src, size)
	if err != nil {
		return err
	}
	comp, err := sniffCompression(src, off)
	if err != nil {
		return err
	}
	dr, closeFn, err := newDecompressor(comp, io.NewSectionReader(src, off, size-off))
	if err != nil {
		return err
	}
	defer closeFn()
	return streamCpioMember(dr, member, maxBytes, setLen, w)
}

// rpmPayloadOffset returns the byte offset of the compressed cpio payload: past
// the 96-byte lead, the signature header (8-byte aligned) and the main header.
func rpmPayloadOffset(src io.ReaderAt, size int64) (int64, error) {
	var lead [4]byte
	if _, err := src.ReadAt(lead[:], 0); err != nil {
		return 0, fmt.Errorf("rpm lead: %w", err)
	}
	if lead[0] != 0xed || lead[1] != 0xab || lead[2] != 0xee || lead[3] != 0xdb {
		return 0, errors.New("rpm: bad lead magic")
	}
	off := int64(96)
	sigLen, err := rpmHeaderLen(src, off)
	if err != nil {
		return 0, err
	}
	off = (off + sigLen + 7) &^ 7 // signature header is padded to an 8-byte boundary
	mainLen, err := rpmHeaderLen(src, off)
	if err != nil {
		return 0, err
	}
	off += mainLen
	if off >= size {
		return 0, errors.New("rpm: payload offset past end")
	}
	return off, nil
}

// rpmHeaderLen returns the byte length of an rpm header section at off, parsing
// only the index/store sizes (not the tags).
func rpmHeaderLen(src io.ReaderAt, off int64) (int64, error) {
	var h [16]byte
	if _, err := src.ReadAt(h[:], off); err != nil {
		return 0, fmt.Errorf("rpm header at %d: %w", off, err)
	}
	if h[0] != 0x8e || h[1] != 0xad || h[2] != 0xe8 {
		return 0, fmt.Errorf("rpm: bad header magic at %d", off)
	}
	nindex := binary.BigEndian.Uint32(h[8:12])
	hsize := binary.BigEndian.Uint32(h[12:16])
	return 16 + int64(nindex)*16 + int64(hsize), nil
}

// sniffCompression identifies a compression stream by its magic bytes at off.
func sniffCompression(src io.ReaderAt, off int64) (string, error) {
	var m [6]byte
	if _, err := src.ReadAt(m[:], off); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("sniff compression: %w", err)
	}
	switch {
	case m[0] == 0x1f && m[1] == 0x8b:
		return "gz", nil
	case m[0] == 0xfd && m[1] == 0x37 && m[2] == 0x7a && m[3] == 0x58 && m[4] == 0x5a && m[5] == 0x00:
		return "xz", nil
	case m[0] == 0x28 && m[1] == 0xb5 && m[2] == 0x2f && m[3] == 0xfd:
		return "zst", nil
	case m[0] == 0x42 && m[1] == 0x5a && m[2] == 0x68:
		return "bz2", nil
	case m[0] == 0x5d && m[1] == 0x00 && m[2] == 0x00:
		return "lzma", nil
	}
	return "", fmt.Errorf("unrecognized payload compression: % x", m)
}

const cpioNewcMagic = "070701"

// streamCpioMember scans a newc-format cpio stream for member and streams it
// out. rpm payloads use this format with "./"-prefixed names, normalised by
// archivePathMatches.
func streamCpioMember(r io.Reader, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	var hdr [110]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, member)
			}
			return fmt.Errorf("cpio header: %w", err)
		}
		if string(hdr[:6]) != cpioNewcMagic {
			return fmt.Errorf("cpio: unsupported format (magic %q)", hdr[:6])
		}
		filesize, err := cpioField(hdr[:], 6)
		if err != nil {
			return err
		}
		namesize, err := cpioField(hdr[:], 11)
		if err != nil {
			return err
		}
		name := make([]byte, namesize)
		if _, err := io.ReadFull(r, name); err != nil {
			return fmt.Errorf("cpio name: %w", err)
		}
		if pad := (4 - (110+namesize)%4) % 4; pad > 0 {
			if _, err := io.CopyN(io.Discard, r, pad); err != nil {
				return fmt.Errorf("cpio name pad: %w", err)
			}
		}
		nm := strings.TrimRight(string(name), "\x00")
		if nm == "TRAILER!!!" {
			return fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, member)
		}
		if archivePathMatches(nm, member) {
			if maxBytes >= 0 && filesize > maxBytes {
				return fmt.Errorf("%w (>%d bytes)", ErrArchiveMemberTooLarge, maxBytes)
			}
			setLen(filesize)
			if _, err := io.Copy(w, io.LimitReader(r, filesize)); err != nil {
				return fmt.Errorf("cpio stream: %w", err)
			}
			return nil
		}
		if _, err := io.CopyN(io.Discard, r, filesize+(4-filesize%4)%4); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: %s", ErrArchiveMemberNotFound, member)
			}
			return fmt.Errorf("cpio skip: %w", err)
		}
	}
}

// cpioField parses the k-th 8-char hex field of a newc cpio header (fields
// follow the 6-byte magic).
func cpioField(hdr []byte, k int) (int64, error) {
	off := 6 + k*8
	v, err := strconv.ParseInt(string(hdr[off:off+8]), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("cpio field %d: %w", k, err)
	}
	return v, nil
}

// streamDebMember reads the deb's outer ar archive, finds its data.tar.* member
// and streams the requested file out of that tarball.
func streamDebMember(src io.ReaderAt, size int64, member string, maxBytes int64, setLen func(int64), w io.Writer) error {
	var magic [8]byte
	if _, err := src.ReadAt(magic[:], 0); err != nil {
		return fmt.Errorf("deb: %w", err)
	}
	if string(magic[:]) != "!<arch>\n" {
		return errors.New("deb: bad ar magic")
	}
	off := int64(8)
	for off+60 <= size {
		var h [60]byte
		if _, err := src.ReadAt(h[:], off); err != nil {
			return fmt.Errorf("deb ar header: %w", err)
		}
		name := strings.TrimRight(strings.TrimSpace(string(h[0:16])), "/")
		msize, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
		if err != nil {
			return fmt.Errorf("deb ar size: %w", err)
		}
		dataOff := off + 60
		if strings.HasPrefix(name, "data.tar") {
			sub := io.NewSectionReader(src, dataOff, msize)
			// cleave records deb members under the ar member's stem, e.g.
			// "data/usr/bin/x"; strip it so the path matches data.tar's own
			// entries ("./usr/bin/x").
			inner := strings.TrimPrefix(member, "data/")
			comp := compFromName(name)
			if comp == "" {
				return streamTarMember(sub, inner, maxBytes, setLen, w)
			}
			return streamCompressedTar(sub, msize, comp, inner, maxBytes, setLen, w)
		}
		off = dataOff + msize + (msize & 1) // ar entries are padded to an even offset
	}
	return fmt.Errorf("%w: data.tar.* not found in deb", ErrArchiveMemberNotFound)
}

// compFromName maps a data.tar.* member name to its compression key.
func compFromName(name string) string {
	switch {
	case strings.HasSuffix(name, ".gz"):
		return "gz"
	case strings.HasSuffix(name, ".xz"):
		return "xz"
	case strings.HasSuffix(name, ".zst"):
		return "zst"
	case strings.HasSuffix(name, ".bz2"):
		return "bz2"
	case strings.HasSuffix(name, ".lzma"):
		return "lzma"
	}
	return ""
}
