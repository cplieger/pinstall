package pinstall

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnpackZipRefusesEscapingEntries pins the extraction guards: an absolute path
// and a traversal entry are both refused, so a hostile archive cannot write outside
// the extraction tree. Refusal rather than sanitising is deliberate -- a legitimate
// archive has no such entry, so quietly rewriting one would hide the archive that
// carries it.
func TestUnpackZipRefusesEscapingEntries(t *testing.T) {
	tests := map[string]string{
		"absolute path":        "/etc/cron.d/pwn",
		"parent traversal":     "../../pwn",
		"nested traversal":     "pkg/../../pwn",
		"absolute traversal":   "/../pwn",
		"deep traversal":       "a/b/../../../pwn",
		"backslash-free trick": "./../pwn",
	}
	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := safeJoin(dir, entry); err == nil {
				t.Errorf("safeJoin(%q) accepted an entry that escapes the extraction directory", entry)
			}
			// The same refusal must hold through the real extraction path.
			archive := filepath.Join(dir, "hostile.zip")
			writeZip(t, archive, map[string]string{entry: "pwned"})
			if err := UnpackZip(context.Background(), archive, filepath.Join(dir, "out")); err == nil {
				t.Errorf("UnpackZip accepted an archive holding %q", entry)
			}
			if exists(filepath.Join(dir, "pwn")) || exists("/etc/cron.d/pwn") {
				t.Fatalf("extraction of %q escaped the extraction directory", entry)
			}
		})
	}
}

// TestSafeJoinAcceptsTheEntriesALegitimateArchiveCarries pins the positive side, so
// the guard cannot be tightened into rejecting real archives: a nested path, a
// dot-prefixed directory, and the explicit "./" root entry some archivers emit.
func TestSafeJoinAcceptsTheEntriesALegitimateArchiveCarries(t *testing.T) {
	dir := t.TempDir()
	tests := map[string]string{
		"nested":            filepath.Join(dir, "pkg", "bin", "tool"),
		"dot-prefixed dir":  filepath.Join(dir, ".config", "x"),
		"single component":  filepath.Join(dir, "tool"),
		"redundant slashes": filepath.Join(dir, "pkg", "tool"),
	}
	inputs := map[string]string{
		"nested":            "pkg/bin/tool",
		"dot-prefixed dir":  ".config/x",
		"single component":  "tool",
		"redundant slashes": "pkg//tool",
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := safeJoin(dir, inputs[name])
			if err != nil {
				t.Fatalf("safeJoin(%q): %v", inputs[name], err)
			}
			if got != want {
				t.Errorf("safeJoin(%q) = %q, want %q", inputs[name], got, want)
			}
		})
	}

	t.Run("the explicit root entry resolves to the extraction dir", func(t *testing.T) {
		got, err := safeJoin(dir, "./")
		if err != nil {
			t.Fatalf("safeJoin(./): %v", err)
		}
		if got != dir {
			t.Errorf("safeJoin(./) = %q, want %q", got, dir)
		}
	})

	t.Run("an empty entry name is refused", func(t *testing.T) {
		if _, err := safeJoin(dir, ""); err == nil {
			t.Error("safeJoin accepted an empty entry name")
		}
	})
}

// TestUnpackZipUnpacksARealArchive pins the happy extraction path, including that the
// executable bit survives (an in-archive installer has to run), that nothing wider
// than owner-write does, and that a nested directory entry is created.
func TestUnpackZipUnpacksARealArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	writeZip(t, archive, map[string]string{
		"pkg/install.sh":    "#!/bin/sh\n",
		"pkg/lib/README.md": "docs\n",
	})
	out := filepath.Join(dir, "out")
	if err := UnpackZip(context.Background(), archive, out); err != nil {
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

// TestUnpackZipHonoursCancellation pins that a large extraction can be abandoned on
// shutdown rather than running to completion.
func TestUnpackZipHonoursCancellation(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	entries := map[string]string{}
	for i := range 50 {
		entries[filepath.Join("pkg", string(rune('a'+i%26))+string(rune('a'+i/26)))] = "body"
	}
	writeZip(t, archive, entries)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := UnpackZip(ctx, archive, filepath.Join(dir, "out")); err == nil {
		t.Error("UnpackZip ran to completion on a cancelled context")
	}
}

// TestUnpackZipRefusesAnUnreadableArchive pins the cheapest failure: a file that is
// not a zip at all is reported, not treated as an empty archive.
func TestUnpackZipRefusesAnUnreadableArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "not-a-zip")
	if err := os.WriteFile(archive, []byte("PK-ish but not really"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := UnpackZip(context.Background(), archive, filepath.Join(dir, "out")); err == nil {
		t.Error("UnpackZip accepted a file that is not a zip archive")
	}
}

// TestExtractFileRefusesAnExhaustedBudget pins the total-size guard's boundary, which
// a whole-archive test cannot reach without building a multi-gigabyte fixture.
func TestExtractFileRefusesAnExhaustedBudget(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.zip")
	writeZip(t, archive, map[string]string{"pkg/big": "0123456789"})
	r, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()

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
			_, err := extractFile(r.File[0], filepath.Join(t.TempDir(), "out"), tc.budget)
			if (err != nil) != tc.wantErr {
				t.Errorf("extractFile budget=%d error = %v, wantErr %v", tc.budget, err, tc.wantErr)
			}
		})
	}
}

// FuzzSafeJoin pins the zip-slip guard on arbitrary entry names: an accepted name
// must resolve strictly inside the extraction directory, and the guard must never
// panic. This is the one boundary in the package that consumes fully untrusted input
// (an archive's own table of contents).
func FuzzSafeJoin(f *testing.F) {
	for _, seed := range []string{
		"pkg/install.sh", "../../etc/passwd", "/etc/passwd", "./", ".", "..",
		"a/../../b", "", "a//b", "a/./b", "\x00", strings.Repeat("../", 100) + "x",
		"a\\b", "....//x", "pkg/", "/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		dir := t.TempDir()
		got, err := safeJoin(dir, name)
		if err != nil {
			return
		}
		if got != dir && !strings.HasPrefix(got, dir+string(filepath.Separator)) {
			t.Fatalf("safeJoin(%q) = %q, which is outside %q", name, got, dir)
		}
		rel, relErr := filepath.Rel(dir, got)
		if relErr != nil {
			t.Fatalf("safeJoin(%q) = %q, which is not relative to %q: %v", name, got, dir, relErr)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("safeJoin(%q) = %q, which escapes %q", name, got, dir)
		}
	})
}

// writeZip builds a zip at path from name -> body. A ".sh" entry gets the executable
// bit, everything else 0o644.
func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range entries {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if strings.HasSuffix(name, ".sh") {
			h.SetMode(0o777)
		} else {
			h.SetMode(0o644)
		}
		w, cerr := zw.CreateHeader(h)
		if cerr != nil {
			t.Fatalf("CreateHeader(%s): %v", name, cerr)
		}
		if _, werr := w.Write([]byte(body)); werr != nil {
			t.Fatalf("Write(%s): %v", name, werr)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
}

// TestExtractFileVerifiesTheModeItAskedFor pins the mode check on the artifacts
// themselves. An artifact leaves the extraction tree by RENAME into the version
// directory, keeping the mode it was created with, and that directory's own
// verified mode only stops another principal REPLACING an entry — not writing to
// one whose stored permissions are wider than the create asked for. A
// group-writable executable in a published version directory is a root-executed
// binary that can be rewritten in place after the archive digest admitted it,
// which is the integrity gate the pin exists to provide.
//
// The widening is real (see preexistingFileIgnoringTheMode, whose witness skips
// the test rather than letting it pass vacuously): open(2) ignores the mode
// argument outright when the path is already occupied, which for an extraction
// tree is what an archive carrying the same entry name twice produces.
func TestExtractFileVerifiesTheModeItAskedFor(t *testing.T) {
	const body = "fake artifact\nversion=2.14.2\n"
	archive := buildZip(t, map[string]zipEntry{"pkg/dispatcher": {body: body, mode: 0o755}})
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	entry := r.File[0]

	dst := filepath.Join(t.TempDir(), "dispatcher")
	preexistingFileIgnoringTheMode(t, dst, 0o666, 0o755)

	if _, err := extractFile(entry, dst, maxExtractBytes); err != nil {
		t.Fatalf("extractFile: %v", err)
	}
	fi, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("lstat the extracted artifact: %v", err)
	}
	if got, want := fi.Mode().Perm(), os.FileMode(0o755); got != want {
		t.Fatalf("extracted artifact mode = %#o, want %#o: a group- and other-writable root-executed binary", got, want)
	}
	if !selfContained(dst) {
		t.Error("the extracted artifact is not a self-contained executable, so it would never be published")
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read the extracted artifact: %v", err)
	}
	if string(raw) != body {
		t.Errorf("extracted content = %q, want %q", raw, body)
	}
}
