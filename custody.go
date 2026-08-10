package pinstall

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// aclXattrs are the extended attributes of the ACL dialects whose POSIX mode is
// NOT an upper bound on write access. Only a non-trivial ACL creates one of these,
// so the presence of a name from this list means the mode cannot be believed.
//
// NFSv4 ACLs are here and POSIX.1e ACLs are deliberately not, and the difference
// is measured rather than assumed:
//
//   - Under POSIX.1e the mode's group bits ARE the ACL mask, and the mask is the
//     ceiling on every named user and named group entry. A directory reading 0755
//     therefore grants no non-owner write however many entries it carries
//     (verified: a named user with rwx under an r-x mask leaves the mode at 0755
//     and the user without write). The owner entry and the other entry are not
//     masked, and both are already checked directly. So for this dialect the mode
//     check is complete and refusing would be over-strict — an ext4 or xfs volume
//     with ordinary ACLs stays perfectly usable.
//   - Under NFSv4 there is no mask with that meaning. A directory reading 0755
//     root:root can carry an inherited entry granting a named non-root user full
//     write (verified on an OpenZFS nfsv4 dataset, which is the class of volume a
//     NAS hands a container). The mode is lossy in the unsafe direction, so this
//     is the dialect that has to be refused.
//
// A filesystem with no ACL support answers listxattr with nothing, or ENOTSUP,
// which reads as "the mode is authoritative" — the right default and the common
// case.
var aclXattrs = []string{
	"system.nfs4_acl",     // NFSv4 ACLs as exposed by the nfs client
	"system.nfs4_acl_xdr", // NFSv4 ACLs as exposed by OpenZFS on Linux
}

// listxattrNames is syscall.Listxattr, replaced in tests. The one seam in this
// file: a filesystem that exposes an NFSv4 ACL is not reachable from an ordinary
// test process, and the refusal it drives is the check's most consequential branch.
var listxattrNames = syscall.Listxattr

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
// Every component of the resolved path, from the filesystem root down to dir
// itself:
//
//   - It is a directory. A non-directory component cannot hold the tree.
//   - Its owner is this process's effective uid, or root. Any other owner may
//     chmod it at will, so its current mode says nothing about its future one.
//   - It is not group- or other-writable, unless it carries the sticky bit. A
//     sticky directory only lets a principal remove or rename entries it owns,
//     so /tmp being 1777 cannot reach a subtree we created inside it.
//   - It carries no access-control list. See below.
//
// # Why an ACL is a refusal rather than an evaluation
//
// A POSIX mode is a lossy projection of an ACL, and the loss runs in the unsafe
// direction: a directory reading 0755 root:root can carry an inherited entry
// granting a named non-root user full write. Measured on a ZFS nfsv4 dataset,
// which is the class of volume a NAS hands a container. A mode-only check would
// therefore pass exactly the tree this package must refuse, and pass it silently.
//
// Reading the mode is not enough, and parsing every ACL dialect is not this
// library's job, so the gate asks a third question instead: is the mode an upper
// bound on write access here? On Linux an ACL that says more than the mode does is
// exposed as an extended attribute, and a trivial ACL — one the mode fully
// describes — has no such attribute at all. [aclXattrs] lists the dialects where
// the answer is no, with the measurements behind that judgement; POSIX.1e ACLs are
// deliberately not among them, so the ordinary Linux volume is unaffected.
//
// The cost is deliberate and bounded: a deployment whose install root sits on an
// NFSv4-ACL volume with a non-trivial ACL is refused until someone decides about
// it. The alternative on offer is a guarantee that quietly does not hold.
//
// dir must already exist — the caller creates the installation root before the
// check rather than after, so the verdict covers the directory that will hold the
// tree instead of the deepest ancestor that happened to exist first. Symlinks are
// resolved before the walk and the resolved chain is what gets judged: a
// symlinked component is not itself interesting, the directory it lands in is.
// Nothing re-resolves a name afterwards, so there is no window between the
// verdict and its use — and changing the chain would need write access to a
// component this walk just proved nobody else has.
func verifyCustody(dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("%w: resolving %s: %w", ErrNoCustody, dir, err)
	}
	euid := os.Geteuid()
	for _, component := range ancestors(resolved) {
		if err := checkComponent(component, euid); err != nil {
			return err
		}
	}
	return nil
}

// ancestors returns every component of an absolute, resolved path from the
// filesystem root down to the path itself, inclusive.
func ancestors(path string) []string {
	out := []string{path}
	for {
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		out = append(out, parent)
		path = parent
	}
	slices.Reverse(out)
	return out
}

// checkComponent judges one directory in the chain.
func checkComponent(path string, euid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: examining %s: %w", ErrNoCustody, path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrNoCustody, path)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: the filesystem reported no ownership information", ErrNoCustody, path)
	}
	if owner := int(stat.Uid); owner != euid && owner != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d rather than uid %d or root, so its permissions are that user's to change",
			ErrNoCustody, path, owner, euid)
	}
	mode := fi.Mode()
	if writable := mode.Perm() & 0o022; writable != 0 && mode&os.ModeSticky == 0 {
		return fmt.Errorf("%w: %s is mode %#o, writable by %s",
			ErrNoCustody, path, mode.Perm(), writableBy(writable))
	}
	if name, found := aclXattrPresent(path); found {
		return fmt.Errorf("%w: %s carries an NFSv4 access-control list (%s), whose entries can grant write access that its mode %#o does not show, so this check cannot see who else may write there",
			ErrNoCustody, path, name, mode.Perm())
	}
	return nil
}

// writableBy names the principals a set of write bits grants, for the error text.
func writableBy(bits os.FileMode) string {
	var who []string
	if bits&0o020 != 0 {
		who = append(who, "its group")
	}
	if bits&0o002 != 0 {
		who = append(who, "everyone")
	}
	return strings.Join(who, " and ")
}

// aclXattrPresent reports whether path carries one of [aclXattrs], and which.
//
// A filesystem without extended-attribute support answers ENOTSUP, which is not a
// failure: it means there is no ACL to hide anything, so the mode is
// authoritative. Any other error is read the same way, because a listxattr this
// process cannot perform on a directory it has just proved it owns is a
// filesystem quirk rather than evidence of a permission this gate should invent.
func aclXattrPresent(path string) (string, bool) {
	buf := make([]byte, 1024)
	n, err := listxattrNames(path, buf)
	if errors.Is(err, syscall.ERANGE) {
		// The name list is longer than the buffer. Ask for the real size rather
		// than guessing, so a directory carrying many attributes cannot push an
		// ACL name out of a fixed window and past this check.
		size, sizeErr := listxattrNames(path, nil)
		if sizeErr != nil || size <= 0 {
			return "", false
		}
		buf = make([]byte, size)
		n, err = listxattrNames(path, buf)
	}
	if err != nil || n <= 0 {
		return "", false
	}
	for name := range strings.SplitSeq(string(buf[:n]), "\x00") {
		if slices.Contains(aclXattrs, name) {
			return name, true
		}
	}
	return "", false
}

// checkCustody re-evaluates custody of the installation tree and records the
// verdict. It runs at the start of every operation rather than once at
// construction, because a volume can be remounted, re-permissioned or re-ACLed
// under a running process, and the verdict is what decides whether an existing
// version directory may be believed.
//
// An installation root that does not exist yet is not a failure and not a pass:
// there is nothing to select from it either way, and install() creates it and asks
// again before it places anything.
func (m *Manager) checkCustody() {
	if _, err := os.Lstat(m.versionsDir); errors.Is(err, os.ErrNotExist) {
		m.setCustody(nil)
		return
	}
	err := verifyCustody(m.versionsDir)
	if err != nil {
		slog.Warn("this process does not exclusively control the installation tree, so a completion sentinel there is not evidence; only versions installed by this process will be activated",
			"package", m.cfg.Release.Name, "root", m.versionsDir, "error", err)
	}
	m.setCustody(err)
}

// setCustody records the verdict under the state lock.
func (m *Manager) setCustody(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.custodyErr = err
}

// requireCustody re-proves custody of the installation root now that it exists,
// and refuses to install when it cannot.
//
// [Config.Untrusted] downgrades the refusal to a warning. That is the caller's
// informed waiver, not a way to silence the check: a version directory in a tree
// somebody else can write is still barred from activation unless THIS process
// installed it, because a sentinel there is forgeable rather than evidence.
func (m *Manager) requireCustody() error {
	err := verifyCustody(m.versionsDir)
	m.setCustody(err)
	if err == nil {
		return nil
	}
	if !m.cfg.Untrusted {
		return err
	}
	slog.Warn("installing into a tree this process does not exclusively control, because Config.Untrusted waives the check",
		"package", m.cfg.Release.Name, "root", m.versionsDir, "error", err)
	return nil
}
