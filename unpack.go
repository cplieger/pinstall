package pinstall

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cplieger/pathinside"
)

// Extraction ceilings. A pinned archive is commonly hundreds of megabytes, so
// these are sanity bounds against a hostile or corrupt response, not tight fits.
const (
	maxExtractBytes   int64 = 3 << 30
	maxExtractEntries       = 20000
)

// Unpacker extracts a verified archive into dir.
//
// A custom implementation MUST refuse absolute and traversing entry names rather
// than sanitising them (a legitimate archive has no such entry, so rewriting one
// hides the archive that carries it), and MUST bound both the entry count and
// the total bytes written. The archive it is handed has already been proved
// against the pinned digest.
type Unpacker func(ctx context.Context, archive, dir string) error

// UnpackZip is the shipped [Unpacker]: archive/zip with traversal, entry-count
// and total-size guards. It is used whenever [Release.Unpack] is nil.
//
// Executable bits survive (an in-archive installer has to run) but nothing wider
// than owner-write does, because the extracted tree lands on a persistent
// volume.
func UnpackZip(ctx context.Context, archive, dir string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("opening the archive: %w", err)
	}
	defer r.Close()
	if len(r.File) > maxExtractEntries {
		return fmt.Errorf("archive holds %d entries, over the %d limit", len(r.File), maxExtractEntries)
	}
	var total int64
	for _, entry := range r.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		written, err := unpackZipEntry(entry, dir, maxExtractBytes-total)
		if err != nil {
			return err
		}
		total += written
	}
	return nil
}

// unpackZipEntry writes one archive entry, creating its parents and refusing to
// exceed budget bytes.
func unpackZipEntry(entry *zip.File, dir string, budget int64) (int64, error) {
	dst, err := safeJoin(dir, entry.Name)
	if err != nil {
		return 0, err
	}
	if entry.FileInfo().IsDir() {
		if err := os.MkdirAll(dst, dirMode); err != nil {
			return 0, fmt.Errorf("creating %s: %w", entry.Name, err)
		}
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), dirMode); err != nil {
		return 0, fmt.Errorf("creating the parent of %s: %w", entry.Name, err)
	}
	return extractFile(entry, dst, budget)
}

// extractFile writes one file entry, refusing to exceed budget bytes.
func extractFile(entry *zip.File, dst string, budget int64) (int64, error) {
	if budget <= 0 {
		return 0, fmt.Errorf("archive exceeds the %d byte extraction limit", maxExtractBytes)
	}
	src, err := entry.Open()
	if err != nil {
		return 0, fmt.Errorf("opening %s in the archive: %w", entry.Name, err)
	}
	defer src.Close()
	mode := entry.Mode().Perm() & 0o755
	if mode&0o100 != 0 {
		mode |= 0o700
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return 0, fmt.Errorf("creating %s: %w", entry.Name, err)
	}
	written, copyErr := io.Copy(out, io.LimitReader(src, budget+1))
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		return written, fmt.Errorf("extracting %s: %w", entry.Name, copyErr)
	case closeErr != nil:
		return written, fmt.Errorf("closing %s: %w", entry.Name, closeErr)
	case written > budget:
		return written, fmt.Errorf("archive exceeds the %d byte extraction limit", maxExtractBytes)
	}
	return written, nil
}

// safeJoin resolves an archive entry name under dir. It REFUSES an absolute path
// or any traversal rather than sanitising one: a legitimate archive has no such
// entries, so quietly rewriting `../../x` into `x` would hide a hostile archive
// instead of reporting it.
//
// Two gates, both on pathinside's separator-precise rule: the entry NAME must not
// escape before it is joined (pathinside.RelEscapes), and the joined path must
// still be inside dir afterwards (pathinside.Inside). The second cannot fail once
// the first has passed for a relative name; it stays as the check on the value
// actually returned, so a future change to how dst is built cannot ship an escape
// on the strength of the name check alone. Absoluteness is refused here rather
// than by pathinside, which deliberately does not judge it.
func safeJoin(dir, name string) (string, error) {
	if name == "" {
		return "", errors.New("archive holds an entry with an empty name")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}
	clean := filepath.Clean(name)
	if clean == "." {
		// Some archives carry an explicit "./" root entry; it resolves to the
		// extraction directory itself, which already exists.
		return dir, nil
	}
	if pathinside.RelEscapes(clean) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	dst := filepath.Join(dir, clean)
	if !pathinside.Inside(dir, dst) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	return dst, nil
}
