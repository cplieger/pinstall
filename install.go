package pinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The placeholders a URL template carries.
const (
	versionPlaceholder = "{version}"
	archPlaceholder    = "{arch}"
)

// Transfer ceilings and watchdogs.
const (
	maxArchiveBytes int64 = 2 << 30
	// stallWindow aborts a transfer that makes no progress for this long. A flat
	// absolute deadline on a large download is a BANDWIDTH FLOOR rather than a
	// hang guard, so lack of progress is what bounds it.
	stallWindow = 60 * time.Second
	// connectTimeout bounds only the handshake, never the body.
	connectTimeout = 20 * time.Second
)

// command is one bounded external command execution. It is the manager's only
// path to a subprocess, so replacing the runner removes every process dependency
// from the tests.
type command struct {
	// Path is the absolute program path.
	Path string
	// Env holds extra variables appended to the process environment.
	Env []string
	// Args are passed as separate elements, never through a shell.
	Args []string
	// Timeout bounds the run; every call site sets one.
	Timeout time.Duration
	// CaptureStderr folds stderr into the returned output, for commands whose
	// diagnostics are worth surfacing.
	CaptureStderr bool
}

// runCommand is the manager's process-execution seam.
type runCommand func(ctx context.Context, c *command) ([]byte, error)

// waitDelay is the grace period after a timed-out command is killed, before its
// output pipes are force-closed.
//
// It is what makes the timeout a real bound. exec.CommandContext kills the child
// on the deadline, but the wait still blocks on the output pipes — and a child
// that forked before dying leaves a grandchild holding the write end, so without
// a delay the call returns only when that grandchild exits. An installer script
// backgrounding a helper is exactly that shape, so a wedged one would stall a
// start indefinitely despite the timeout. A package variable so the tests can
// shorten it.
var waitDelay = 5 * time.Second

// execRunner is the production runner: one bounded, context-cancellable
// subprocess with no shell in the path.
func execRunner(ctx context.Context, c *command) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	// #nosec G204 -- the path and args come from the caller's own profile and
	// the operator-supplied pin, never from request data, and they are passed as
	// separate argv elements so no shell parses them.
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.WaitDelay = waitDelay
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	if c.CaptureStderr {
		return cmd.CombinedOutput()
	}
	return cmd.Output()
}

// httpFetch is the production archive fetcher: a bounded body and a stall
// watchdog instead of an absolute deadline.
func httpFetch(ctx context.Context, url string, dst io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("building the archive request: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout:   connectTimeout,
			ResponseHeaderTimeout: connectTimeout,
			ForceAttemptHTTP2:     true,
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching the archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("fetching the archive: unexpected status %s", resp.Status)
	}
	return copyWithStallGuard(cancel, dst, io.LimitReader(resp.Body, maxArchiveBytes), stallWindow)
}

// copyWithStallGuard streams src into dst, cancelling the transfer when no bytes
// arrive for window. It refuses an empty body: a zero-length "success" is a
// partial download, and the digest check would otherwise report it as a mismatch
// and hide the real cause.
func copyWithStallGuard(cancel context.CancelFunc, dst io.Writer, src io.Reader, window time.Duration) error {
	progress := make(chan struct{}, 1)
	done := make(chan struct{})
	stalled := make(chan struct{})
	go func() {
		timer := time.NewTimer(window)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-progress:
				timer.Reset(window)
			case <-timer.C:
				close(stalled)
				cancel()
				return
			}
		}
	}()

	written, err := io.Copy(dst, readerFunc(func(p []byte) (int, error) {
		n, rerr := src.Read(p)
		if n > 0 {
			select {
			case progress <- struct{}{}:
			default:
			}
		}
		return n, rerr
	}))
	close(done)

	select {
	case <-stalled:
		return fmt.Errorf("archive transfer made no progress for %s and was aborted", window)
	default:
	}
	if err != nil {
		return fmt.Errorf("reading the archive body: %w", err)
	}
	if written == 0 {
		return errors.New("archive body was empty (partial download?)")
	}
	return nil
}

// readerFunc adapts a function to io.Reader so the copy can observe progress
// without a bespoke type.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// archiveURL is the pinned archive's absolute URL. The version is pinned rather
// than a floating "latest" so a given deployment is reproducible and the digest
// check is meaningful.
func (m *Manager) archiveURL() string {
	url := strings.ReplaceAll(m.urlTemplate, versionPlaceholder, m.cfg.Version)
	return strings.ReplaceAll(url, archPlaceholder, m.archToken)
}

// stageTree is one in-progress installation: the extracted archive, a private
// home for an in-archive installer, and the version directory that will be
// renamed into place. All three live under the installation root, so the publish
// stays a same-filesystem rename rather than a copy.
type stageTree struct {
	root       string
	extract    string
	home       string
	versionDir string
}

// install performs one complete installation attempt. On every failure path
// nothing outside the staging tree is left behind and the versions already on the
// volume keep serving.
//
// The archive is downloaded and verified into a process-local temp dir BEFORE any
// staging tree exists, so on a digest mismatch nothing has been created under the
// installation root at all — not even an empty directory.
func (m *Manager) install(ctx context.Context) error {
	slog.Info("installing", "package", m.cfg.Release.Name, "version", m.cfg.Version, "arch", m.cfg.GOARCH)
	if m.cfg.Release.Notice != "" {
		slog.Info(m.cfg.Release.Notice, "package", m.cfg.Release.Name, "version", m.cfg.Version)
	}

	work, mkErr := os.MkdirTemp("", "pinstall-*")
	if mkErr != nil {
		return fmt.Errorf("creating the download temp dir: %w", mkErr)
	}
	defer os.RemoveAll(work)

	archive := filepath.Join(work, "archive")
	if err := m.downloadArchive(ctx, archive); err != nil {
		return err
	}

	stage, stageErr := m.newStage()
	if stageErr != nil {
		return stageErr
	}
	defer os.RemoveAll(stage.root)

	if err := m.unpack(ctx, archive, stage.extract); err != nil {
		return fmt.Errorf("unpacking the archive: %w", err)
	}
	src, srcErr := m.runInstaller(ctx, stage)
	if srcErr != nil {
		return srcErr
	}
	if err := m.gateStaged(ctx, filepath.Join(src, m.primary)); err != nil {
		return err
	}
	if err := m.assemble(stage, src); err != nil {
		return err
	}
	if err := m.publish(stage); err != nil {
		return err
	}
	m.mu.Lock()
	m.installed[m.cfg.Version] = true
	m.mu.Unlock()
	slog.Info("installed", "package", m.cfg.Release.Name, "version", m.cfg.Version,
		"dir", m.versionDir(m.cfg.Version))
	return nil
}

// downloadArchive fetches the pinned archive and proves it is the artifact the
// pin names. Verification is the whole point: nothing downstream re-checks the
// digest, and nothing is placed on the persistent volume until it passes.
func (m *Manager) downloadArchive(ctx context.Context, dst string) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("creating the archive file: %w", err)
	}
	sum := sha256.New()
	// Digest the bytes as they land, so a large archive is read once.
	fetchErr := m.fetch(ctx, m.archiveURL(), io.MultiWriter(f, sum))
	closeErr := f.Close()
	switch {
	case fetchErr != nil:
		return fetchErr
	case closeErr != nil:
		return fmt.Errorf("closing the archive file: %w", closeErr)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if got != m.digest {
		return fmt.Errorf("%w: arch=%s expected=%s actual=%s (bump the version and every digest literal together)",
			ErrDigestMismatch, m.cfg.GOARCH, m.digest, got)
	}
	slog.Info("archive SHA-256 verified against the pinned digest",
		"package", m.cfg.Release.Name, "arch", m.cfg.GOARCH, "sha256", got)
	return nil
}

// newStage creates the staging tree under the installation root.
func (m *Manager) newStage() (*stageTree, error) {
	if err := os.MkdirAll(m.versionsDir, dirMode); err != nil {
		return nil, fmt.Errorf("creating the installation root: %w", err)
	}
	root, err := os.MkdirTemp(m.versionsDir, stagePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("creating the staging tree: %w", err)
	}
	stage := &stageTree{
		root:       root,
		extract:    filepath.Join(root, "x"),
		home:       filepath.Join(root, "home"),
		versionDir: filepath.Join(root, "v"),
	}
	for _, dir := range []string{stage.extract, stage.home} {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return nil, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	return stage, nil
}

// runInstaller runs the archive's own installer against the PRIVATE staging home,
// so the artifacts it drops there never land on PATH or in the real home before
// they are verified. It returns the directory the artifacts are expected in.
//
// The installer's exit code is deliberately not fatal: an upstream installer
// commonly touches shell profiles and other surfaces that legitimately fail in a
// minimal container. What matters is whether the artifacts it produced pass the
// staged gates. With no installer configured the archive itself already holds the
// artifacts and no subprocess runs at all.
func (m *Manager) runInstaller(ctx context.Context, stage *stageTree) (string, error) {
	inst := m.cfg.Release.Installer
	if inst == nil {
		return filepath.Join(stage.extract, m.cfg.Release.ArtifactDir), nil
	}
	script := filepath.Join(stage.extract, inst.Path)
	if !selfContained(script) {
		return "", fmt.Errorf("the archive holds no executable installer at %s", inst.Path)
	}
	homeEnv := inst.HomeEnv
	if homeEnv == "" {
		homeEnv = "HOME"
	}
	timeout := inst.Timeout
	if timeout <= 0 {
		timeout = defaultInstallerTimeout
	}
	out, err := m.run(ctx, &command{
		Path:          script,
		Env:           []string{homeEnv + "=" + stage.home},
		Args:          inst.Args,
		Timeout:       timeout,
		CaptureStderr: true,
	})
	if err != nil {
		slog.Warn("the archive's installer reported a failure; continuing to the staged-artifact gates, which decide",
			"package", m.cfg.Release.Name, "installer", inst.Path,
			"error", err, "output", truncate(string(out), 2000))
	}
	return filepath.Join(stage.home, m.cfg.Release.ArtifactDir), nil
}

// gateStaged refuses a staged candidate that is not the pinned, self-contained
// primary artifact, and refuses one whose required assertions do not hold.
func (m *Manager) gateStaged(ctx context.Context, staged string) error {
	if !selfContained(staged) {
		return fmt.Errorf("no self-contained executable at %s (absent, not executable, or a symlink whose target dies with the staging cleanup)", staged)
	}
	got, err := m.probeVersion(ctx, staged)
	if err != nil {
		return fmt.Errorf("probing the staged artifact: %w", err)
	}
	if got != m.cfg.Version {
		return fmt.Errorf("staged artifact reports version %q, want %q", got, m.cfg.Version)
	}
	// The required assertions are asserted against the STAGED artifact before
	// publication, so a candidate they cannot hold on never becomes a version
	// directory. This is not a substitute for the every-start reassertion in
	// finish: an assertion's effect lives in the package's mutable
	// configuration, so it has to be re-proved on every start too.
	return m.applyRequiredAssertions(ctx, staged)
}

// assemble moves the artifacts out of src into the staged version directory and
// makes the result DURABLE, in the order the protocol requires: every file is
// written and Synced, then the ".complete" sentinel is written and Synced LAST,
// then the directory itself is Synced. Only after that may publish rename it into
// place.
//
// Atomic visibility is not crash durability: a successful rename proves no
// concurrent lookup sees a half-populated directory, it does not prove the new
// directory entry or the file data reached stable storage. Any sync failure —
// ENOSPC included — fails the install, which leaves every complete version
// already on the volume untouched.
func (m *Manager) assemble(stage *stageTree, src string) error {
	if err := os.MkdirAll(stage.versionDir, dirMode); err != nil {
		return fmt.Errorf("creating the staged version directory: %w", err)
	}
	moved := make([]string, 0, len(m.cfg.Require)+len(m.cfg.Optional))
	for _, name := range m.cfg.Require {
		dst, err := m.moveArtifact(src, stage.versionDir, name)
		if err != nil {
			return fmt.Errorf("required artifact %s: %w", name, err)
		}
		moved = append(moved, dst)
	}
	for _, name := range m.cfg.Optional {
		dst, err := m.moveArtifact(src, stage.versionDir, name)
		if err != nil {
			slog.Warn("optional artifact not installed",
				"package", m.cfg.Release.Name, "artifact", name, "error", err)
			continue
		}
		moved = append(moved, dst)
	}
	for _, path := range moved {
		if err := m.fsync(path); err != nil {
			return fmt.Errorf("syncing %s: %w", filepath.Base(path), err)
		}
	}
	if err := m.writeSentinel(stage.versionDir); err != nil {
		return err
	}
	if err := m.fsync(stage.versionDir); err != nil {
		return fmt.Errorf("syncing the staged version directory: %w", err)
	}
	return nil
}

// moveArtifact moves one artifact from src into dst, refusing anything that is
// not a self-contained executable: a symlink would pass an existence and
// executability check and then dangle the moment the staging tree is removed.
func (m *Manager) moveArtifact(src, dst, name string) (string, error) {
	from := filepath.Join(src, name)
	if !selfContained(from) {
		return "", errors.New("absent, not executable, or a symlink into the staging tree")
	}
	to := filepath.Join(dst, name)
	if err := m.rename(from, to); err != nil {
		return "", err
	}
	return to, nil
}

// writeSentinel writes the ".complete" marker LAST, holding the version whose
// full artifact set the directory contains. It lives inside the directory it
// describes, so it cannot drift from those artifacts.
func (m *Manager) writeSentinel(dir string) error {
	path := filepath.Join(dir, sentinelName)
	if err := os.WriteFile(path, []byte(m.cfg.Version+"\n"), fileMode); err != nil {
		return fmt.Errorf("writing the completion sentinel: %w", err)
	}
	if err := m.fsync(path); err != nil {
		return fmt.Errorf("syncing the completion sentinel: %w", err)
	}
	return nil
}

// publish renames the staged version directory to its final name and syncs the
// parent, completing the durability protocol. Pruning may only run after this
// returns nil.
func (m *Manager) publish(stage *stageTree) error {
	dst := m.versionDir(m.cfg.Version)
	// The destination can exist here for exactly one reason: the pinned
	// directory was rejected by the version probe (a replaced artifact under an
	// intact sentinel) and is being replaced. It is untrusted, so removing it is
	// correct, and the retained predecessor is what covers the crash window
	// between the remove and the rename.
	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clearing the previous %s directory: %w", m.cfg.Version, err)
	}
	if err := m.rename(stage.versionDir, dst); err != nil {
		return fmt.Errorf("publishing the version directory: %w", err)
	}
	if err := m.fsync(m.versionsDir); err != nil {
		return fmt.Errorf("syncing the installation root: %w", err)
	}
	return nil
}

// writeFileDurably writes data to path through a temp file in the same
// directory: write, sync, rename, sync the parent.
func (m *Manager) writeFileDurably(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := m.fsync(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := m.rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return m.fsync(dir)
}

// fsyncPath commits the file or directory at path to stable storage. fsync on a
// read-only descriptor is valid on Linux, so one helper covers both.
func fsyncPath(path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is always built from Root and this package's own constants.
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	return nil
}

// truncate bounds a diagnostic string so a runaway installer log cannot flood the
// log pipeline.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "...(truncated)"
}
