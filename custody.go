//go:build linux

package pinstall

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// verifyCustody proves that only this process's identity (or root) can modify
// dir, by checking dir and every ancestor of its resolved path. It reads and
// judges; it never changes anything.
//
// # Why this is a precondition, and why nothing is repaired
//
// Every guarantee this package makes reduces to one claim: the artifact it
// activates came out of an archive that matched the pinned digest. The digest is
// checked once, on bytes in flight; from then on the claim rests entirely on the
// installation tree not being modifiable by anyone else. The completion sentinel
// is a plain file, so it is forgeable rather than evidence. The version probe
// re-runs whatever binary is at the path now. Neither survives a principal who
// can write into the tree, so custody is not one defence among several — it is
// the whole of it.
//
// That makes a precondition the right shape and repair the wrong one. A library
// that chmods a directory it found too permissive has already lost: it asserts
// authority over a tree whose configuration says another principal has authority
// too, and the operator who wrote that configuration is never told. Verify once
// and refuse is what OpenSSH does with StrictModes, what sudo does with the
// ownership of sudoers, and what git does with safe.directory. This follows them.
//
// # What is checked
//
// EVERY directory the kernel passes through to reach dir, followed one component at a
// time from "/": each symlink's target is taken in place, and ".." moves to the parent of
// the directory actually reached, never cleaned lexically, so a ".." after a link cannot
// steer the walk away from a directory a later open() goes through. A directory holding a
// link the resolution follows is as load-bearing as the tree itself: whoever can write it
// repoints the chain, and the next MkdirTemp, OpenRoot or Rename lands in a tree of their
// choosing.
//
// For each of those components:
//
//   - It is a directory, or a symlink (judged by [checkSymlink]). A non-directory
//     component cannot hold the tree.
//   - Its owner is this process's effective uid, or root. A directory's owner may
//     widen its mode whenever it likes, so another user's directory says nothing
//     about what its permissions will be a moment from now.
//   - Nobody the caller has not accounted for can write it, by mode or by
//     access-control list. An ANCESTOR is exempted from that one question when it
//     carries the sticky bit, because sticky restricts removal and renaming to the
//     owner of each entry, and that is what makes /tmp (1777 everywhere) usable. The
//     exemption does not cover a grant that lets someone else clear the sticky bit:
//     taking the directory, or rewriting its list. The installation root itself is
//     not exempted at all: sticky says nothing about CREATE, and anyone who can
//     create entries there can plant a version directory.
//   - It carries no access-control list of a dialect whose mode is not an upper
//     bound on write access. See below.
//
// The artifacts inside a version directory are checked separately, at publish and at
// activation, because a file's mode is independent of its parent's: directory write
// permission governs creating, removing and renaming entries, not writing to the
// contents of one that already exists.
//
// dir must already exist — the caller creates the installation root before the check
// rather than after, so the verdict covers the directory that will hold the tree
// instead of the deepest ancestor that happened to exist first.
//
// # What it does not establish
//
// A verdict is a statement about one instant, and the operations it authorises happen
// afterwards. What makes that gap safe is not the timing but the content of the
// verdict: replacing any component of any of those chains needs write access to the
// directory holding it, and the walk has refused every chain where another principal has
// that. The one place another principal CAN create entries is a sticky ancestor others can
// write, and sticky is exactly the rule that stops them touching an entry they do not own —
// which is why the ownership of a symlink is demanded there and nowhere else. Root is
// outside the model entirely, as it is for every check of this kind.
//
// It also cannot see a filesystem that does not make the mode its access decision at
// all — a cifs mount with noperm, a FUSE filesystem without default_permissions —
// where the numbers read here are decoration. No mode-and-xattr inspection can detect
// that from inside the process; it belongs to the operator, which is what
// [Config.InstallWithoutCustody] is for.
func verifyCustody(dir string, trust trustedWriters) error {
	return verifyCustodyChain(dir, trust, true)
}

// verifyCustodyChain is [verifyCustody] with the one fact only the caller knows stated
// explicitly: whether the last component of dir IS the installation root.
//
// It has to be told, because the walk can otherwise see only POSITION, and position is
// not the question. The last component is the installation root when
// [Manager.requireCustody] walks m.versionsDir; it is an ordinary ANCESTOR when
// [Manager.checkCustody] walks the nearest directory that exists because the root does
// not exist yet. The two are held to different rules — an ancestor may earn the sticky
// exemption and the root may not (see [checkComponent]) — so deciding leaf-ness from the
// position judged that ancestor by the installation-root rule. On a /tmp-shaped (1777)
// shared parent that made the FIRST start record a custody refusal and therefore skip the
// one-shot legacy purge, which is the one start it can run on; a later start, once the
// versions directory existed, passed the very same directory as an ancestor.
func verifyCustodyChain(dir string, trust trustedWriters, judgeLeafStrictly bool) error {
	if dir == "" {
		return fmt.Errorf("%w: an empty path", ErrNoCustody)
	}
	if !filepath.IsAbs(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("%w: resolving %s: %w", ErrNoCustody, dir, err)
		}
		dir = wd + "/" + dir // not Join: Join cleans ".." lexically
	}
	w := &custodyWalk{trust: trust, euid: os.Geteuid(), at: "/"}
	if err := checkComponent(w.at, w.euid, false, false, trust); err != nil {
		return err
	}
	w.shared = sharedSticky(w.at, w.euid, trust)
	pending := pathComponents(dir)
	for len(pending) > 0 {
		next, err := w.step(pending[0])
		if err != nil {
			return err
		}
		pending = append(next, pending[1:]...)
	}
	if judgeLeafStrictly {
		return checkComponent(w.at, w.euid, true, false, trust)
	}
	return nil
}

// custodyWalk is verifyCustodyChain's position, following the path as the kernel
// resolves it: each symlink's target in place, and ".." to the parent of the
// directory actually reached, never lexically. Every directory above at was judged
// on the way down.
type custodyWalk struct {
	at     string
	trust  trustedWriters
	euid   int
	hops   int
	shared bool // at is a sticky directory a stranger can write
}

// step moves through one component, returning the components a symlink's target
// puts in front of the rest of the path.
func (w *custodyWalk) step(name string) ([]string, error) {
	if name == ".." {
		w.at = filepath.Dir(w.at)
		w.shared = sharedSticky(w.at, w.euid, w.trust)
		return nil, nil
	}
	next := filepath.Join(w.at, name) // one name, no "..": nothing to clean
	fi, err := os.Lstat(next)
	if err != nil {
		return nil, fmt.Errorf("%w: examining %s: %w", ErrNoCustody, next, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		if cerr := checkComponent(next, w.euid, false, w.shared, w.trust); cerr != nil {
			return nil, cerr
		}
		w.at = next
		w.shared = sharedSticky(w.at, w.euid, w.trust)
		return nil, nil
	}
	if cerr := checkComponent(next, w.euid, false, w.shared, w.trust); cerr != nil {
		return nil, cerr // a symlink: checkComponent judges its owner (checkSymlink)
	}
	w.hops++
	if w.hops > maxSymlinkHops {
		return nil, fmt.Errorf("%w: resolving %s: the chain has not resolved after %d symbolic links: %w",
			ErrNoCustody, next, maxSymlinkHops, syscall.ELOOP)
	}
	target, err := os.Readlink(next)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the symlink %s: %w", ErrNoCustody, next, err)
	}
	if filepath.IsAbs(target) {
		w.at = "/"
		w.shared = sharedSticky(w.at, w.euid, w.trust)
	}
	return pathComponents(target), nil
}

// maxSymlinkHops is Linux's SYMLOOP_MAX, so a chain this refuses is one open()
// would refuse too.
const maxSymlinkHops = 40

// pathComponents splits path into its names, dropping empty ones and ".", and
// keeping "..", which only the walk can resolve.
func pathComponents(path string) []string {
	var out []string
	for c := range strings.SplitSeq(path, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// sharedSticky reports whether path DENOTES a sticky directory that an identity the caller
// has not accounted for can write, following a symlink to answer it.
//
// Following is the whole point. A symlink's own mode is 0777 with no sticky bit on
// every Linux system, so asking the link would answer "not sticky" however sticky the
// directory it points at is — and the next component down lives in that directory, not
// in the link. Reading this off the component's own Lstat mode is what let an
// attacker-owned symlink inside /tmp be accepted when it was reached through a private
// link to /tmp, while being correctly refused when named directly.
//
// The WRITE half of the question goes through [writersOf], the same enumeration the walk
// judges a component with, so the mode AND the access-control list decide it. A mode-only
// answer was fail-OPEN on precisely the filesystems this package parses lists for: a
// directory at 1755 carrying an EVERYONE@ WRITE_DATA ACE is one anybody can create entries
// in, so a stranger's symlink inside it can be repointed at a tree of their choosing, and
// the mode says 0755 and nothing else. It also asks the question against the DECLARED writer
// set rather than against the mode bits alone, so an ancestor whose only writer is an
// identity the caller declared is not shared, exactly as it is not shared anywhere else in
// this walk.
//
// An answer that could not be obtained — a stat that failed, a list that could not be
// evaluated — counts as shared, which is the FAIL-CLOSED direction: the only thing this fact
// controls is whether [checkSymlink] demands ownership of the next component, so treating
// the unknown as shared can add a demand and can never drop one. The reverse — the shape
// this function first shipped with — let a transient stat failure on the parent silently
// retire that demand.
//
// The list is read here even though [checkComponent] has just read one for the same string,
// because whenever the component is a symlink those are two different objects: that read
// judged the link, this one judges the directory it points at. Only a sticky directory gets
// as far as the read, so the cost is one extra getxattr on a /tmp-shaped ancestor and none
// anywhere else.
func sharedSticky(path string, euid int, trust trustedWriters) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return true
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSticky == 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		return true
	}
	_, shared := trust.firstStranger(writers, euid)
	return shared
}

// checkComponent judges one component of a path chain.
//
// installRoot marks the component that IS the installation root, which is held to a
// stricter rule than its ancestors: it is never exempted from the write question, however
// sticky it is. It is the last component of the chain only when the caller is walking the
// installation root itself, so [walkChain] is told rather than inferring it. parentShared
// says the containing directory was sticky and writable by somebody the caller has not
// accounted for, which is the only case where a symlink's ownership is load-bearing.
func checkComponent(path string, euid int, installRoot, parentShared bool, trust trustedWriters) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: examining %s: %w", ErrNoCustody, path, err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: the filesystem reported no ownership information", ErrNoCustody, path)
	}
	mode := fi.Mode()
	owner := int(stat.Uid)
	if mode&os.ModeSymlink != 0 {
		return checkSymlink(path, owner, euid, parentShared, trust)
	}
	// For a directory, ownership is load-bearing on its own: the owner can widen the
	// mode whenever it likes, so a directory belonging to another user tells us nothing
	// about what its permissions will be a moment from now.
	if !trust.allowsOwner(owner, euid) {
		return fmt.Errorf("%w: %s is owned by uid %d rather than uid %d or root, so its permissions are that user's to change%s",
			ErrNoCustody, path, owner, euid, trust.hint())
	}
	if !mode.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrNoCustody, path)
	}
	// A sticky ANCESTOR others can write is not a boundary: sticky restricts removal and
	// renaming to the owner of each entry, so a principal who can create entries beside
	// ours cannot rename ours away. That exemption is what makes /tmp (1777 on every
	// Linux system) a usable place to root an installation, and it is an exemption from
	// the WRITE question only — whether anyone else can write here is answered anyway, by
	// [sharedSticky], because it decides whether a symlink inside this directory has to be
	// ours.
	//
	// The installation root ITSELF gets no such exemption. Sticky says nothing about
	// CREATE, and the root's contents are the thing being protected: anyone able to
	// create entries there can plant a complete-looking version directory, which
	// selection would otherwise accept as an installed version.
	if !installRoot && mode&os.ModeSticky != 0 {
		// The exemption holds only while nobody else can clear the sticky bit: WRITE_OWNER
		// takes the directory and then chmod, and WRITE_ACL grants itself the rest. Removal
		// itself stays the kernel's sticky rule; [nfs4ControlMask] owns which grants count.
		controllers, ctlErr := controllersOf(path, stat)
		if ctlErr != nil {
			return fmt.Errorf("%w: %w", ErrNoCustody, ctlErr)
		}
		if stranger, found := trust.firstStranger(controllers, euid); found {
			return fmt.Errorf("%w: %s, mode %#o, is sticky, but its access-control list lets %s take its ownership or rewrite that list, and either removes the protection the sticky bit was providing%s",
				ErrNoCustody, path, mode.Perm(), stranger, trust.hint())
		}
		return nil
	}
	writers, err := writersOf(path, fi, stat)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoCustody, err)
	}
	if stranger, found := trust.firstStranger(writers, euid); found {
		return fmt.Errorf("%w: %s, mode %#o, can be modified by %s%s%s",
			ErrNoCustody, path, mode.Perm(), stranger, stickyNote(mode, installRoot), trust.hint())
	}
	return nil
}

// stickyNote explains why the sticky bit did not save the installation root, for the one
// error where an operator is most likely to think it should have. It is reached only when
// the subject IS the root: an ancestor is exempted from this question rather than told
// about it.
func stickyNote(mode os.FileMode, installRoot bool) string {
	if installRoot && mode&os.ModeSticky != 0 {
		return ", and the sticky bit stops another principal renaming the installation root away but not creating a version directory inside it"
	}
	return ""
}

// checkSymlink judges a symlink on the path.
//
// A symlink's own mode grants nothing on Linux, and its OWNERSHIP grants nothing either
// in the usual case: replacing it requires write permission on the directory holding it,
// which the walk has already refused to grant anyone else. Requiring the link to be ours
// as well would refuse a perfectly private chain that happens to contain another user's
// link inside a directory nobody can write — a real deployment shape, refused for no gain.
//
// The exception is a sticky parent others can write, where sticky's rule is precisely "only
// the entry's owner (or the directory's, or root) may remove or rename it". A
// foreign-owned link there CAN be replaced by its owner, so who owns it is exactly the
// question. Whether the parent is such a directory is [sharedSticky]'s answer, and it reads
// the access-control list as well as the mode: a 1755 directory carrying an EVERYONE@ write
// entry is one anybody can plant a link in.
func checkSymlink(path string, owner, euid int, parentShared bool, trust trustedWriters) error {
	if !parentShared {
		return nil
	}
	if !trust.allowsOwner(owner, euid) {
		return fmt.Errorf("%w: %s is a symlink owned by uid %d inside a sticky directory others can write, so that user can repoint it at a tree of their choosing%s",
			ErrNoCustody, path, owner, trust.hint())
	}
	return nil
}

// checkCustody re-evaluates custody of the installation tree and records the
// verdict. It runs at the start of every operation rather than once at
// construction, because a volume can be remounted, re-permissioned or re-ACLed
// under a running process, and the verdict is what decides whether an existing
// version directory may be believed.
//
// When the installation root does not exist yet the nearest ancestor that DOES is
// judged instead. Recording a clean verdict for an absent directory would be the
// wrong kind of convenient: the legacy purge and the state record both write under
// Root before the versions directory is ever created, and they would then run on the
// strength of a verdict about nothing. The ancestor chain is what will hold the tree,
// so it is a real answer to the same question — but it is judged AS an ancestor, which
// is why the strictness is passed explicitly rather than left to the walk's position;
// see [verifyCustodyChain].
func (m *Manager) checkCustody() {
	dir := nearestExisting(m.versionsDir)
	err := verifyCustodyChain(dir, m.trust, dir == m.versionsDir)
	if err != nil {
		slog.Warn("this process does not exclusively control the installation tree, so a completion sentinel there is not evidence; only versions installed by this process will be activated",
			"package", m.cfg.Release.Name, "root", m.versionsDir, "error", err)
	}
	m.setCustody(err)
}

// nearestExisting returns dir, or its closest ancestor that exists. The filesystem
// root always does, so this terminates.
func nearestExisting(dir string) string {
	for {
		if _, err := os.Lstat(dir); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return dir
		}
		dir = parent
	}
}

// setCustody records the verdict under the state lock.
func (m *Manager) setCustody(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.custodyErr = err
}

// custodyVerdict returns the last recorded verdict.
func (m *Manager) custodyVerdict() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.custodyErr
}

// requireCustody re-proves custody of the installation root now that it exists,
// and refuses to install when it cannot.
//
// [Config.InstallWithoutCustody] downgrades the refusal to a warning. That is the
// caller's informed waiver, not a way to silence the check: a version directory in a tree
// somebody else can write is still barred from activation unless THIS process installed
// it, because a sentinel there is forgeable rather than evidence.
func (m *Manager) requireCustody() error {
	err := verifyCustody(m.versionsDir, m.trust)
	m.setCustody(err)
	if err == nil {
		return nil
	}
	if !m.cfg.InstallWithoutCustody {
		return err
	}
	slog.Warn("installing into a tree this process does not exclusively control, because Config.InstallWithoutCustody waives the check",
		"package", m.cfg.Release.Name, "root", m.versionsDir, "error", err)
	return nil
}
