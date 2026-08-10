package pinstall

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnpackZipRefusesEscapingEntries pins the containment guard: an absolute
// path, a traversal, and a name mixing the two are all REFUSED rather than
// sanitised, and nothing lands outside the extraction directory.
//
// Refusal rather than rewriting is deliberate — a legitimate archive has no such
// entry, so quietly turning `../../x` into `x` would hide the archive that carries
// it. The refusal is now the kernel's, through the destination [os.Root], which is
// why this test asserts on the OUTCOME (an error, and an untouched sibling tree)
// rather than on a lexical helper.
func TestUnpackZipRefusesEscapingEntries(t *testing.T) {
	tests := map[string]string{
		"absolute path":      "/etc/cron.d/pwn",
		"parent traversal":   "../pwn",
		"deep traversal":     "../../pwn",
		"nested traversal":   "pkg/../../pwn",
		"dot-slash parent":   "./../pwn",
		"absolute traversal": "/../pwn",
		"deeper traversal":   "a/b/../../../pwn",
	}
	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			out := filepath.Join(base, "out")
			if err := os.Mkdir(out, 0o755); err != nil {
				t.Fatalf("mkdir the extraction dir: %v", err)
			}
			archive := zipReader(t, map[string]zipEntry{entry: {body: "pwned", mode: 0o644}})
			if err := UnpackZip(context.Background(), archive, openRoot(t, out)); err == nil {
				t.Errorf("UnpackZip accepted an archive holding %q", entry)
			}
			// The escape target for every case above resolves to the parent of
			// the extraction directory, or to a fixed absolute path.
			if exists(filepath.Join(base, "pwn")) || exists("/etc/cron.d/pwn") {
				t.Fatalf("extraction of %q escaped the extraction directory", entry)
			}
		})
	}
}

// TestUnpackZipAcceptsTheEntriesALegitimateArchiveCarries pins the positive side,
// so containment cannot be tightened into rejecting real archives: a nested path,
// a dot-prefixed directory, a bare name, redundant separators, and the explicit
// "./" root entry some archivers emit.
func TestUnpackZipAcceptsTheEntriesALegitimateArchiveCarries(t *testing.T) {
	entries := map[string]zipEntry{
		"tool":              {body: "bare\n", mode: 0o755},
		"pkg/bin/tool":      {body: "nested\n", mode: 0o755},
		".config/x":         {body: "dotted\n", mode: 0o644},
		"pkg//tool":         {body: "redundant\n", mode: 0o644},
		"./":                {dir: true},
		"pkg/lib/README.md": {body: "docs\n", mode: 0o644},
	}
	out := t.TempDir()
	if err := UnpackZip(context.Background(), zipReader(t, entries), openRoot(t, out)); err != nil {
		t.Fatalf("UnpackZip refused a legitimate archive: %v", err)
	}
	for _, want := range []string{"tool", "pkg/bin/tool", ".config/x", "pkg/tool", "pkg/lib/README.md"} {
		if !exists(filepath.Join(out, filepath.FromSlash(want))) {
			t.Errorf("entry %q was not extracted", want)
		}
	}
}

// TestUnpackZipUnpacksARealArchive pins the happy extraction path: the executable
// bit survives (an in-archive installer has to run), nothing wider than
// owner-write does, and a nested directory entry is created.
func TestUnpackZipUnpacksARealArchive(t *testing.T) {
	out := t.TempDir()
	archive := zipReader(t, map[string]zipEntry{
		"pkg/install.sh":    {body: "#!/bin/sh\n", mode: 0o777},
		"pkg/lib/README.md": {body: "docs\n", mode: 0o644},
	})
	if err := UnpackZip(context.Background(), archive, openRoot(t, out)); err != nil {
		t.Fatalf("UnpackZip: %v", err)
	}
	fi, err := os.Stat(filepath.Join(out, "pkg", "install.sh"))
	if err != nil {
		t.Fatalf("Stat install.sh: %v", err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("install.sh mode = %v, want the owner-execute bit preserved", fi.Mode().Perm())
	}
	if fi.Mode().Perm()&0o022 != 0 {
		t.Errorf("install.sh mode = %v, want nothing wider than owner-write", fi.Mode().Perm())
	}
	if !exists(filepath.Join(out, "pkg", "lib", "README.md")) {
		t.Error("the nested archive entry was not extracted")
	}
}

// TestUnpackZipRefusesADuplicateEntryName pins the O_EXCL create. An archive
// carrying the same name twice is not a conflict to resolve by letting the last
// one win: open(2) ignores the mode argument outright when the path is already
// occupied, so a second entry would land with whatever mode the first one got,
// and a rewritten artifact is exactly what the pin exists to prevent.
func TestUnpackZipRefusesADuplicateEntryName(t *testing.T) {
	raw := buildZipOrdered(t, []namedEntry{
		{name: "pkg/tool", zipEntry: zipEntry{body: "first\n", mode: 0o755}},
		{name: "pkg/tool", zipEntry: zipEntry{body: "second\n", mode: 0o666}},
	})
	out := t.TempDir()
	err := UnpackZip(context.Background(), bytesReader(raw), openRoot(t, out))
	if err == nil {
		t.Fatal("UnpackZip accepted an archive carrying the same entry name twice")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Errorf("UnpackZip error = %v, want one wrapping os.ErrExist", err)
	}
	body, readErr := os.ReadFile(filepath.Join(out, "pkg", "tool"))
	if readErr != nil {
		t.Fatalf("read the extracted artifact: %v", readErr)
	}
	if string(body) != "first\n" {
		t.Errorf("extracted body = %q, want the first entry's content left untouched", body)
	}
}

// TestUnpackZipHonoursCancellation pins that a large extraction can be abandoned
// on shutdown rather than running to completion.
func TestUnpackZipHonoursCancellation(t *testing.T) {
	entries := map[string]zipEntry{}
	for i := range 50 {
		entries["pkg/"+string(rune('a'+i%26))+string(rune('a'+i/26))] = zipEntry{body: "body", mode: 0o644}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := UnpackZip(ctx, zipReader(t, entries), openRoot(t, t.TempDir())); err == nil {
		t.Error("UnpackZip ran to completion on a cancelled context")
	}
}

// TestUnpackZipRefusesAnUnreadableArchive pins the cheapest failure: bytes that
// are not a zip at all are reported, not treated as an empty archive.
func TestUnpackZipRefusesAnUnreadableArchive(t *testing.T) {
	if err := UnpackZip(context.Background(), bytesReader([]byte("PK-ish but not really")), openRoot(t, t.TempDir())); err == nil {
		t.Error("UnpackZip accepted bytes that are not a zip archive")
	}
}

// TestUnpackZipRefusesTooManyEntries pins the entry-count ceiling on a real
// archive that exceeds it, rather than by lowering the limit for the test: the
// ceiling is the production value or the test proves nothing about it. The
// fixture is cheap because every entry is empty and stored uncompressed.
func TestUnpackZipRefusesTooManyEntries(t *testing.T) {
	entries := make([]namedEntry, 0, maxExtractEntries+1)
	for i := range maxExtractEntries + 1 {
		entries = append(entries, namedEntry{name: fmt.Sprintf("e%d", i), zipEntry: zipEntry{mode: 0o644}})
	}
	raw := buildZipOrdered(t, entries)
	out := t.TempDir()
	err := UnpackZip(context.Background(), bytesReader(raw), openRoot(t, out))
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("UnpackZip error = %v, want an entry-count refusal", err)
	}
	left, readErr := os.ReadDir(out)
	if readErr != nil {
		t.Fatalf("ReadDir the extraction dir: %v", readErr)
	}
	if len(left) != 0 {
		t.Errorf("the extraction dir holds %d entries, want nothing written before the count was refused", len(left))
	}
}

// TestExtractFileRefusesAnExhaustedBudget pins the total-size guard's boundary,
// which a whole-archive test cannot reach without a multi-gigabyte fixture.
func TestExtractFileRefusesAnExhaustedBudget(t *testing.T) {
	raw := buildZip(t, map[string]zipEntry{"big": {body: "0123456789", mode: 0o644}})
	r, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}

	tests := map[string]struct {
		budget  int64
		wantErr bool
	}{
		"budget exhausted":       {budget: 0, wantErr: true},
		"budget negative":        {budget: -1, wantErr: true},
		"budget below the entry": {budget: 4, wantErr: true},
		"budget exactly enough":  {budget: 10},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := extractFile(r.File[0], "big", openRoot(t, t.TempDir()), tc.budget)
			if (err != nil) != tc.wantErr {
				t.Errorf("extractFile budget=%d error = %v, wantErr %v", tc.budget, err, tc.wantErr)
			}
		})
	}
}

// TestEntryTargetCannotRescueAnEscapingName pins the property that makes
// normalising an entry name safe. Cleaning a name is normally how a zip-slip guard
// gets defeated, so the rule has to be explicit: [path.Clean] collapses a ".."
// only when a real parent precedes it, which means a name that escapes still
// escapes afterwards and the destination root remains the judge.
func TestEntryTargetCannotRescueAnEscapingName(t *testing.T) {
	escaping := []string{
		"../pwn", "../../pwn", "./../pwn", "/etc/passwd", "/../pwn",
		"a/../../pwn", strings.Repeat("../", 100) + "x",
	}
	for _, name := range escaping {
		got, err := entryTarget(name)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(got, "../") && got != ".." && !strings.HasPrefix(got, "/") {
			t.Errorf("entryTarget(%q) = %q, which no longer escapes: cleaning rescued a hostile name", name, got)
		}
	}

	contained := map[string]string{
		"pkg//tool":   "pkg/tool",
		"./pkg/tool":  "pkg/tool",
		"a/b/../../c": "c",
		"pkg/":        "pkg",
		"tool":        "tool",
		"./":          ".",
	}
	for name, want := range contained {
		got, err := entryTarget(name)
		if err != nil {
			t.Errorf("entryTarget(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("entryTarget(%q) = %q, want %q", name, got, want)
		}
	}

	if _, err := entryTarget(""); err == nil {
		t.Error("entryTarget accepted an empty entry name")
	}
}

// FuzzUnpackZipEntryNames pins containment on arbitrary entry names: whatever an
// archive's table of contents carries, the extraction either fails or writes
// strictly inside the destination, and it never panics. This is the one boundary
// in the package that consumes fully untrusted input.
//
// The oracle is the filesystem rather than a lexical predicate: after every call
// the parent of the extraction directory must hold nothing new. That is a strictly
// stronger invariant than the one the deleted safeJoin fuzz target asserted, which
// could only ever check a string.
func FuzzUnpackZipEntryNames(f *testing.F) {
	for _, seed := range []string{
		"pkg/install.sh", "../../etc/passwd", "/etc/passwd", "./", ".", "..",
		"a/../../b", "", "a//b", "a/./b", "\x00", strings.Repeat("../", 100) + "x",
		"a\\b", "....//x", "pkg/", "/", "C:/x", "\\\\?\\x", "pkg/./../../x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		base := t.TempDir()
		out := filepath.Join(base, "out")
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatalf("mkdir the extraction dir: %v", err)
		}
		raw, err := zipWithRawName(name)
		if err != nil {
			// Not every string is a name archive/zip can encode; that is the
			// writer's business, not the extractor's.
			return
		}
		root, rootErr := os.OpenRoot(out)
		if rootErr != nil {
			t.Fatalf("OpenRoot: %v", rootErr)
		}
		defer root.Close()
		_ = UnpackZip(context.Background(), bytesReader(raw), root)

		siblings, readErr := os.ReadDir(base)
		if readErr != nil {
			t.Fatalf("ReadDir the parent of the extraction dir: %v", readErr)
		}
		for _, e := range siblings {
			if e.Name() != "out" {
				t.Fatalf("entry %q created %q beside the extraction directory", name, e.Name())
			}
		}
	})
}

// openRoot opens dir as the confined destination an [Unpacker] is handed.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// bytesReader wraps raw archive bytes in the shape an [Unpacker] is handed.
func bytesReader(raw []byte) *io.SectionReader {
	return io.NewSectionReader(bytes.NewReader(raw), 0, int64(len(raw)))
}

// zipReader builds an in-memory zip from entries and returns it as an unpacker
// would receive it.
func zipReader(t *testing.T, entries map[string]zipEntry) *io.SectionReader {
	t.Helper()
	return bytesReader(buildZip(t, entries))
}
