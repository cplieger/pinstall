package pinstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cplieger/atomicfile/v2"
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
// installation root at all — not even an empty directory. It stays open from the
// digest check through the extraction, so the unpacker reads the bytes that were
// proved rather than whatever the archive's name resolves to by then.
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

	archive, dlErr := m.downloadArchive(ctx, filepath.Join(work, "archive"))
	if dlErr != nil {
		return dlErr
	}
	defer func() { _ = archive.close() }()

	stage, stageErr := m.newStage()
	if stageErr != nil {
		return stageErr
	}
	defer os.RemoveAll(stage.root)

	if err := m.unpack(ctx, archive.reader(), stage.extract); err != nil {
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
//
// It returns the archive still OPEN, because the proof and the extraction have to
// be about the same bytes. Digesting a file and then handing its PATH to the
// unpacker proves nothing: the name can be pointed at another inode in between,
// and the extraction would take whatever is there now — the same defeat as
// swapping the installed binary, one step earlier. The descriptor these bytes
// were written and hashed through is the one the unpacker reads, so there is no
// name left to swap. The caller closes it.
//
// O_EXCL is what makes that descriptor exclusively this install's. dst is a fresh
// name in a private temp directory, so anything already sitting there — a symlink
// into a directory this process can write included — is not a file to truncate
// but a reason to fail.
func (m *Manager) downloadArchive(ctx context.Context, dst string) (*verifiedArchive, error) {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return nil, fmt.Errorf("creating the archive file: %w", err)
	}
	sum := sha256.New()
	// Digest the bytes as they land, so a large archive is read once.
	if fetchErr := m.fetch(ctx, m.archiveURL(), io.MultiWriter(f, sum)); fetchErr != nil {
		_ = f.Close()
		return nil, fetchErr
	}
	// The verified length is the descriptor's own write offset, not a stat of the
	// path: it counts the bytes that went through the hash, so the reader handed
	// out below cannot reach past what was proved.
	size, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("measuring the archive that was written: %w", err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if got != m.digest {
		_ = f.Close()
		return nil, fmt.Errorf("%w: arch=%s expected=%s actual=%s (bump the version and every digest literal together)",
			ErrDigestMismatch, m.cfg.GOARCH, m.digest, got)
	}
	slog.Info("archive SHA-256 verified against the pinned digest",
		"package", m.cfg.Release.Name, "arch", m.cfg.GOARCH, "sha256", got)
	return &verifiedArchive{file: f, size: size}, nil
}

// verifiedArchive is a downloaded archive whose digest matched, held open on the
// descriptor its bytes were written and hashed through, with the exact length
// that hash covers.
//
// The PATH is deliberately not a field. Nothing downstream re-checks the digest,
// so the only thing making the extraction trustworthy is that it reads these
// bytes rather than whatever the archive's name resolves to by then.
type verifiedArchive struct {
	file *os.File
	size int64
}

// reader returns a reader over exactly the verified bytes. Each call builds a
// fresh one: a [io.SectionReader] carries its own offset, so sequential reading
// by an unpacker moves nothing on the shared descriptor.
func (a *verifiedArchive) reader() *io.SectionReader {
	return io.NewSectionReader(a.file, 0, a.size)
}

// close releases the descriptor. The archive file itself goes with the temp
// directory the caller removes.
func (a *verifiedArchive) close() error { return a.file.Close() }

// newStage creates the staging tree under the installation root.
//
// The staging root's own stored mode is verified, and it is the one check that
// covers the whole subtree: at 0700 nothing else on the host can even traverse
// into it, so the modes of the directories inside it are not a boundary. Widened
// to 0770 it becomes one, and the exposure is worse than a published directory's
// — the extracted tree holds the archive's own installer, which this package
// EXECUTES, so a group member who can write there runs code as whatever user the
// install runs as. os.MkdirTemp asks for 0700 and, like every other mkdir, does
// not read the result back.
//
// A staging root whose mode cannot be verified is removed before returning
// rather than left for the next start's prunePartials: the failure means that
// directory is writable by others, and leaving one sitting under the
// installation root is the exposure itself.
func (m *Manager) newStage() (*stageTree, error) {
	if err := m.ensureVersionsDir(); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(m.versionsDir, stagePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("creating the staging tree: %w", err)
	}
	if err := enforceDirMode(root, stageMode); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("the staging tree is not private to this install: %w", err)
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

// ensureVersionsDir creates the installation root and, when THIS call created it,
// verifies the mode the filesystem stored for it.
//
// The root is the directory every version tree sits in, so group-writable it
// defeats every check below it: another principal can rename a published version
// directory away and put its own tree at that name, and nothing re-digests what is
// inside the substitute.
//
// It is created in two steps rather than one os.MkdirAll only so this call can
// tell that it was the creator — MkdirAll returns nil for a directory that was
// already there, and os.Mkdir's fs.ErrExist is that answer without the
// stat-then-act window a pre-check would open. The same directories are created at
// the same requested mode either way. A PRE-EXISTING root is deliberately left
// alone: an operator may have widened it on purpose, repairing another principal's
// directory is not this library's call, and [Config.Untrusted] is the channel that
// already exists for reporting a root that was writable by others — it refuses to
// activate any version directory this process did not install itself.
func (m *Manager) ensureVersionsDir() error {
	if err := os.MkdirAll(filepath.Dir(m.versionsDir), dirMode); err != nil {
		return fmt.Errorf("creating the installation root: %w", err)
	}
	switch err := os.Mkdir(m.versionsDir, dirMode); {
	case err == nil:
	case errors.Is(err, fs.ErrExist):
		return nil
	default:
		return fmt.Errorf("creating the installation root: %w", err)
	}
	if err := enforceDirMode(m.versionsDir, dirMode); err != nil {
		return fmt.Errorf("the installation root was created writable by others: %w", err)
	}
	return nil
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
//
// The staged directory's stored mode is verified before anything moves into it,
// and that verdict is what the PUBLISHED directory carries: publish renames this
// same inode into place, and a rename cannot change a mode. A directory born
// group-writable would let a group member replace the root-executed binary the
// digest check just admitted, so a mode the filesystem refused to store fails the
// install like any other durability failure.
func (m *Manager) assemble(stage *stageTree, src string) error {
	if err := os.MkdirAll(stage.versionDir, dirMode); err != nil {
		return fmt.Errorf("creating the staged version directory: %w", err)
	}
	if err := enforceDirMode(stage.versionDir, dirMode); err != nil {
		return fmt.Errorf("the staged version directory would be published writable by others: %w", err)
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
//
// fileMode is verified on the open descriptor before any bytes go in, because the
// sentinel's own mode is the only thing protecting its contents: the version
// directory's verified 0755 stops another principal creating, replacing or
// removing entries, not writing to an entry whose own mode the filesystem
// widened. A group-writable sentinel is rewritable, and a sentinel that no longer
// names its directory makes a COMPLETE version read as a partial — which
// prunePartials then deletes, costing the operator the retained fallback set the
// availability posture depends on.
func (m *Manager) writeSentinel(dir string) error {
	path := filepath.Join(dir, sentinelName)
	if err := writeFileVerifiedMode(path, []byte(m.cfg.Version+"\n"), fileMode); err != nil {
		return fmt.Errorf("writing the completion sentinel: %w", err)
	}
	if err := m.fsync(path); err != nil {
		return fmt.Errorf("syncing the completion sentinel: %w", err)
	}
	return nil
}

// writeFileVerifiedMode writes data to path with mode, proving the filesystem
// STORED mode before the content is written rather than trusting the mode the
// create asked for. Same rule as [enforceDirMode], on the descriptor the create
// returned: the file never holds content while its permissions are wider than
// asked for, so there is no window in which a widened file has anything worth
// rewriting.
func writeFileVerifiedMode(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- path is built from Root and this package's own constants.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := atomicfile.EnforceMode(f, mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
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

// enforceDirMode proves that the filesystem STORED want for the directory this
// process just created, instead of trusting that it honoured the mode the mkdir
// asked for.
//
// A mode argument is a REQUEST, not a result. mkdir(2) passes it through umask,
// and a filesystem carrying an inheritable group ACL can store something wider
// than what was asked for regardless: measured on a ZFS nfs4acl dataset an
// inheritable group@:rwx ACE yields 0770 from a 0o700 mkdir, and tightening the
// parent does not cover it. Consumers of this library keep their installation
// root on exactly such a volume, and nothing here ever read the mode back.
//
// What that costs is the integrity gate the whole version-addressed layout
// exists to provide. A version directory holds the artifacts a consumer executes
// AS ROOT, admitted only because the archive they came out of matched the pinned
// digest. Born group-writable, that directory lets any member of the widening
// group replace the binary AFTER the digest check passed, and nothing downstream
// would notice: the completion sentinel is a plain file, so it is forgeable
// rather than evidence, and the version probe re-reads whatever binary is at the
// path now. The mode is the only thing standing between a verified install and a
// substituted one.
//
// The verdict comes from an OPEN HANDLE — atomicfile.EnforceMode fchmods and
// then fstats the same descriptor — so a name swapped in between the repair and
// the check cannot make it certify a different directory. O_NOFOLLOW makes the
// kernel refuse a symlink at the final component and O_DIRECTORY refuses
// anything that is not a directory; O_NONBLOCK is what keeps a planted FIFO from
// parking this call in open(2) indefinitely with no writer on the other end.
//
// It is only ever called on a directory THIS process created, which is what
// makes the chmod inside it safe: no other writer has ever held that name, so
// the repair cannot be taking over a directory somebody else made. A directory
// that was already there when the install started — an installation root a
// consumer's entrypoint creates and hardens — is never handed to it; see
// ensureVersionsDir for why repairing one is not this library's call.
func enforceDirMode(dir string, want os.FileMode) error {
	// #nosec G304 -- dir is always a path this package just created under Root,
	// never request data, and the open flags refuse a link or a non-directory in
	// the kernel rather than after the fact.
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("opening %s to verify the mode it was created with: %w", dir, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := atomicfile.EnforceMode(f, want); err != nil {
		return err
	}
	return nil
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
