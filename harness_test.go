package pinstall

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pin under test and the two versions used as "already on the volume".
const (
	pinnedVersion = "2.14.2"
	prevVersion   = "2.14.1"
	oldVersion    = "2.14.0"
)

// The harness's primary profile: a package whose archive ships an installer that
// drops the artifacts into a private home. It is deliberately NOT a real
// upstream — the library must name no vendor.
const (
	toolName          = "toolkit"
	toolSidecar       = "toolkit-chat"
	toolExtra         = "toolkit-term"
	toolInstaller     = "pkg/install.sh"
	toolArtifactDir   = ".local/bin"
	mandatoryName     = "pkg.disableAutoupdates"
	toolURLTemplate   = "https://example.invalid/{version}/tool-{arch}.zip"
	testLinkDir       = "bin"
	sixtyFourHexChars = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// TestMain silences the manager's slog output for the whole package: every
// install path logs, and the volume drowns real failures in test output.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// toolRelease is the primary test profile.
func toolRelease() Release {
	return Release{
		Name:        toolName,
		URLTemplate: toolURLTemplate,
		ArchTokens:  map[string]string{"amd64": "x86_64-linux", "arm64": "aarch64-linux"},
		Installer: &ArchiveInstaller{
			Path:    toolInstaller,
			Args:    []string{"--no-confirm"},
			Timeout: time.Minute,
		},
		ArtifactDir: toolArtifactDir,
		ProbeArgs:   []string{"--version"},
		Notice:      "toolkit is third-party content; installing it accepts its licence",
		Mandatory:   []Assertion{{Name: mandatoryName, Args: []string{"settings", mandatoryName, "true"}}},
	}
}

// fakeEnv is the test double for every boundary the manager crosses: the archive
// fetch, subprocess execution, fsync, rename, the clock and the sleep. Together
// they make an install run end to end with no network, no real archive and no
// real package.
type fakeEnv struct {
	t    *testing.T
	root string

	release  Release
	require  []string
	optional []string

	archive []byte
	digest  string

	// produces maps the artifact names the fake installer writes into the
	// staging home to the version each one reports. Unused by a profile with no
	// installer, whose artifacts come out of the archive itself.
	produces map[string]string
	// installerFails makes the installer report a failure AND write nothing, the
	// shape that fails the staged gates.
	installerFails bool
	// probeAnswerFor renders the version a fake artifact encodes into the shape
	// that package's probe prints.
	probeAnswerFor func(version string) string

	onFetch  func(dst io.Writer) error
	onProbe  func(bin string) ([]byte, error)
	onAssert func(bin string, args []string) error
	onSync   func(path string) error
	onRename func(oldpath, newpath string) error

	mu      sync.Mutex
	calls   []string
	fetches int
	slept   []time.Duration
}

// newEnv wires an env to one profile and one archive.
func newEnv(t *testing.T, release Release, archive []byte, require, optional []string) *fakeEnv {
	t.Helper()
	sum := sha256.Sum256(archive)
	return &fakeEnv{
		t:              t,
		root:           t.TempDir(),
		release:        release,
		require:        require,
		optional:       optional,
		archive:        archive,
		digest:         hex.EncodeToString(sum[:]),
		probeAnswerFor: func(v string) string { return toolName + " " + v + "\n" },
	}
}

// newFakeEnv is the primary env: the installer-shipping profile, one required
// sidecar and one optional extra.
func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	env := newEnv(t, toolRelease(), installerArchive(t), []string{toolSidecar}, []string{toolExtra})
	env.produces = map[string]string{
		toolName:    pinnedVersion,
		toolSidecar: pinnedVersion,
		toolExtra:   pinnedVersion,
	}
	return env
}

// zipEntry is one file in a test archive.
type zipEntry struct {
	body string
	mode os.FileMode
}

// buildZip builds a real zip in memory, so extraction is exercised for real
// while the runner seam stands in for executing what comes out of it.
func buildZip(t *testing.T, entries map[string]zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		e := entries[name]
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(e.mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("zip CreateHeader(%s): %v", name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("zip Write(%s): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

// installerArchive is an archive whose only useful content is the installer the
// manager execs.
func installerArchive(t *testing.T) []byte {
	t.Helper()
	return buildZip(t, map[string]zipEntry{
		toolInstaller:  {body: "#!/bin/sh\nexit 0\n", mode: 0o755},
		"pkg/NOTICE":   {body: "toolkit\n", mode: 0o644},
		"pkg/lib/x.so": {body: "binary\n", mode: 0o644},
	})
}

// manager builds a manager wired to this env, with every seam replaced.
func (e *fakeEnv) manager(mutate ...func(*Config)) *Manager {
	e.t.Helper()
	m, err := New(e.config(mutate...))
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	e.wire(m)
	return m
}

// config is the env's Config, before New validates it.
func (e *fakeEnv) config(mutate ...func(*Config)) *Config {
	cfg := &Config{
		Release:      e.release,
		Version:      pinnedVersion,
		Digests:      map[string]string{"amd64": e.digest, "arm64": e.digest},
		Root:         e.root,
		GOARCH:       "amd64",
		Require:      e.require,
		Optional:     e.optional,
		LinkDir:      testLinkDir,
		RetryBackoff: time.Millisecond,
		MaxAttempts:  1,
	}
	for _, f := range mutate {
		f(cfg)
	}
	return cfg
}

// wire replaces every seam on m with this env's double.
func (e *fakeEnv) wire(m *Manager) {
	m.fetch = e.fetch
	m.run = e.run
	m.fsync = e.fsync
	m.rename = e.rename
	m.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	m.sleep = e.sleep
}

func (e *fakeEnv) record(format string, args ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, fmt.Sprintf(format, args...))
}

func (e *fakeEnv) called() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

func (e *fakeEnv) countCalls(substr string) int {
	n := 0
	for _, c := range e.called() {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func (e *fakeEnv) fetch(_ context.Context, url string, dst io.Writer) error {
	e.mu.Lock()
	e.fetches++
	e.mu.Unlock()
	e.record("fetch %s", url)
	if e.onFetch != nil {
		return e.onFetch(dst)
	}
	_, err := dst.Write(e.archive)
	return err
}

func (e *fakeEnv) fetchCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetches
}

// run dispatches on the shape of the command: the archive's installer, the
// release's own probe argv, or an assertion.
func (e *fakeEnv) run(_ context.Context, c *command) ([]byte, error) {
	switch {
	case e.isInstaller(c.Path):
		e.record("installer")
		return e.runInstaller(c)
	case slices.Equal(c.Args, e.release.ProbeArgs):
		e.record("probe %s", c.Path)
		if e.onProbe != nil {
			return e.onProbe(c.Path)
		}
		return e.probeAnswer(c.Path)
	default:
		e.record("assert %s on %s", strings.Join(c.Args, " "), c.Path)
		if e.onAssert != nil {
			return nil, e.onAssert(c.Path, c.Args)
		}
		return nil, nil
	}
}

// isInstaller reports whether path is the profile's in-archive installer.
func (e *fakeEnv) isInstaller(path string) bool {
	inst := e.release.Installer
	return inst != nil && strings.HasSuffix(path, filepath.FromSlash(inst.Path))
}

// runInstaller stands in for the archive's installer: it writes the configured
// artifacts into the private staging home the manager handed it.
func (e *fakeEnv) runInstaller(c *command) ([]byte, error) {
	home := ""
	want := e.release.Installer.HomeEnv
	if want == "" {
		want = "HOME"
	}
	for _, kv := range c.Env {
		if rest, ok := strings.CutPrefix(kv, want+"="); ok {
			home = rest
		}
	}
	if home == "" {
		return nil, fmt.Errorf("the installer ran without %s pointed at a private home: %v", want, c.Env)
	}
	if e.installerFails {
		return []byte("boom\n"), fmt.Errorf("the installer failed")
	}
	binDir := filepath.Join(home, e.release.ArtifactDir)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return nil, err
	}
	for name, version := range e.produces {
		if err := writeFakeBinary(filepath.Join(binDir, name), version); err != nil {
			return nil, err
		}
	}
	return []byte("installed\n"), nil
}

func (e *fakeEnv) fsync(path string) error {
	e.record("fsync %s", path)
	if e.onSync != nil {
		if err := e.onSync(path); err != nil {
			return err
		}
	}
	return fsyncPath(path)
}

func (e *fakeEnv) rename(oldpath, newpath string) error {
	e.record("rename %s -> %s", oldpath, newpath)
	if e.onRename != nil {
		if err := e.onRename(oldpath, newpath); err != nil {
			return err
		}
	}
	return os.Rename(oldpath, newpath)
}

func (e *fakeEnv) sleep(_ context.Context, d time.Duration) error {
	e.mu.Lock()
	e.slept = append(e.slept, d)
	e.mu.Unlock()
	return nil
}

func (e *fakeEnv) sleeps() []time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.slept)
}

// writeFakeBinary writes an executable file that records the version it answers
// the probe with, so a test can "tamper" with an installed artifact by rewriting
// its content.
func writeFakeBinary(path, version string) error {
	// An executable bit is the point: selfContained rejects anything else.
	return os.WriteFile(path, []byte(fakeBinaryBody(version)), 0o755)
}

// fakeBinaryBody is the content of a fake artifact at one version.
func fakeBinaryBody(version string) string {
	return "fake artifact\nversion=" + version + "\n"
}

// probeAnswer reads the version a fake artifact encodes and renders it in the
// shape this profile's probe prints.
func (e *fakeEnv) probeAnswer(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "version="); ok {
			return []byte(e.probeAnswerFor(v)), nil
		}
	}
	return nil, fmt.Errorf("%s is not a fake artifact", path)
}

// placeVersion writes a COMPLETE version directory straight onto the volume,
// standing in for an install a previous start finished.
func (e *fakeEnv) placeVersion(version string, names ...string) string {
	e.t.Helper()
	dir := e.versionDir(version)
	if len(names) == 0 {
		names = append([]string{e.release.binary()}, e.require...)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	for _, n := range names {
		if err := writeFakeBinary(filepath.Join(dir, n), version); err != nil {
			e.t.Fatalf("writeFakeBinary(%s): %v", n, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, sentinelName), []byte(version+"\n"), 0o600); err != nil {
		e.t.Fatalf("write sentinel: %v", err)
	}
	return dir
}

// placePartial writes a version directory with the artifacts but NO sentinel: the
// shape an interrupted install leaves behind.
func (e *fakeEnv) placePartial(version string) string {
	e.t.Helper()
	dir := e.versionDir(version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	for _, n := range append([]string{e.release.binary()}, e.require...) {
		if err := writeFakeBinary(filepath.Join(dir, n), version); err != nil {
			e.t.Fatalf("writeFakeBinary(%s): %v", n, err)
		}
	}
	return dir
}

func (e *fakeEnv) versionsRoot() string {
	return filepath.Join(e.root, e.release.Name+versionsSuffix)
}

func (e *fakeEnv) versionDir(version string) string {
	return filepath.Join(e.versionsRoot(), version)
}

func (e *fakeEnv) statePath() string {
	return filepath.Join(e.root, e.release.Name+stateSuffix)
}

// versionDirs lists the non-staging entries under the installation root.
func (e *fakeEnv) versionDirs() []string {
	entries, err := os.ReadDir(e.versionsRoot())
	if err != nil {
		return nil
	}
	out := []string{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			out = append(out, entry.Name())
		}
	}
	return out
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// digestOf is the SHA-256 of an archive a test built itself, for the cases that
// replace the harness's default archive.
func digestOf(archive []byte) string {
	sum := sha256.Sum256(archive)
	return hex.EncodeToString(sum[:])
}

// setgidParentThatWidens makes dir setgid and then PROVES that a mkdir inside it
// stores a mode it did not ask for. It skips the calling test when the widening
// does not happen.
//
// The skip is the point. A create-path mode test on a filesystem that honours
// every request cannot distinguish a directory whose stored mode was VERIFIED
// from one whose mode was merely requested, so it would pass vacuously and go on
// passing after the verification was deleted. Failing as INVALID is the only
// honest outcome there.
//
// The widening is real rather than mocked: Linux propagates S_ISGID from a setgid
// directory to every new subdirectory, so os.Mkdir(child, 0o700) genuinely stores
// setgid|0700. It is the same class of surprise as the inheritable group ACL that
// motivated the checks under test — measured on a ZFS nfs4acl dataset, an
// inheritable group@:rwx ACE yields 0770 from a 0o700 mkdir — and unlike that one
// it needs no special filesystem to reproduce.
func setgidParentThatWidens(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700|os.ModeSetgid); err != nil {
		t.Fatalf("chmod %s setgid: %v", dir, err)
	}
	witness := filepath.Join(dir, ".mode-witness")
	if err := os.Mkdir(witness, 0o700); err != nil {
		t.Fatalf("mkdir the witness under %s: %v", dir, err)
	}
	fi, err := os.Lstat(witness)
	if err != nil {
		t.Fatalf("lstat the witness: %v", err)
	}
	if err := os.RemoveAll(witness); err != nil {
		t.Fatalf("remove the witness: %v", err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Skipf("this kernel did not widen a 0o700 mkdir under a setgid parent (stored %v); "+
			"the test cannot distinguish a verified create from an unverified one here", fi.Mode())
	}
}

// preexistingFileIgnoringTheMode creates path at wide and then PROVES that an
// O_CREATE|O_TRUNC open asking for ask leaves the stored mode at wide. It leaves
// path in place at wide, for the production call under test to be handed, and
// skips the calling test when the kernel honours the mode argument after all.
//
// This is the file half of the same "a mode argument is a REQUEST" bug, in the
// one form this environment can demonstrate. The widening that motivated the
// checks is an inheritable group ACL storing 0775 for a 0o755 create, which needs
// a filesystem carrying such an ACL (there is no setfacl here, and overlayfs
// would not carry one). open(2) ignoring the mode argument outright when the path
// already exists is the same defect with the same consequence — a file left
// group- and other-writable by a create that reported success — and it is
// reachable in production wherever a path can already be occupied, which for the
// extraction tree is an archive carrying the same entry name twice.
func preexistingFileIgnoringTheMode(t *testing.T, path string, wide, ask os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, nil, wide); err != nil {
		t.Fatalf("pre-create %s: %v", path, err)
	}
	// WriteFile's own mode goes through umask, so set the wide mode explicitly
	// rather than assuming the process umask left it alone.
	if err := os.Chmod(path, wide); err != nil {
		t.Fatalf("chmod %s to %#o: %v", path, wide, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, ask)
	if err != nil {
		t.Fatalf("open the witness at %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close the witness: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat the witness: %v", err)
	}
	if fi.Mode().Perm() == ask.Perm() {
		t.Skipf("this kernel applied the O_CREATE mode %#o to an already-existing file; "+
			"the test cannot distinguish a verified create from an unverified one here", ask.Perm())
	}
}
