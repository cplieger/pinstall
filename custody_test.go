package pinstall

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestVerifyCustodyAcceptsATreeOnlyThisProcessCanWrite pins the positive side, and
// it is the case that must not regress into a refusal: an ordinary private
// directory under the system temp root passes, INCLUDING the world-writable sticky
// ancestor every such path has.
//
// The sticky exemption is load-bearing rather than a convenience. /tmp is 1777 on
// every Linux system, and a sticky directory only lets a principal remove or rename
// entries it owns, so a subtree we created inside one is not reachable. Without the
// exemption this check would refuse the most common install root there is.
func TestVerifyCustodyAcceptsATreeOnlyThisProcessCanWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tools", "pkg-versions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := verifyCustody(dir); err != nil {
		t.Fatalf("verifyCustody refused a private tree: %v", err)
	}

	// The witness: the chain really does include a world-writable ancestor, so
	// the sticky exemption is what let this pass rather than the absence of one.
	sticky := false
	for _, component := range ancestors(mustEval(t, dir)) {
		fi, err := os.Lstat(component)
		if err != nil {
			t.Fatalf("lstat %s: %v", component, err)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky != 0 {
			sticky = true
		}
	}
	if !sticky {
		t.Skip("no world-writable sticky ancestor on this system, so the exemption is untested here")
	}
}

// TestVerifyCustodyRefusesAWritableComponent pins the refusal on every shape of
// non-owner write, at every depth of the chain. A component anywhere above the
// installation root is enough: a principal who can write to a parent renames the
// version tree away and puts its own at that name, and nothing downstream re-digests
// the substitute.
func TestVerifyCustodyRefusesAWritableComponent(t *testing.T) {
	tests := map[string]struct {
		mode os.FileMode
		want string
	}{
		"group writable":   {mode: 0o775, want: "its group"},
		"other writable":   {mode: 0o757, want: "everyone"},
		"both writable":    {mode: 0o777, want: "its group and everyone"},
		"group write only": {mode: 0o720, want: "its group"},
	}
	for name, tc := range tests {
		for _, depth := range []string{"the root itself", "a parent"} {
			t.Run(name+", "+depth, func(t *testing.T) {
				base := t.TempDir()
				parent := filepath.Join(base, "tools")
				root := filepath.Join(parent, "pkg-versions")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				offender := root
				if depth == "a parent" {
					offender = parent
				}
				if err := os.Chmod(offender, tc.mode); err != nil {
					t.Fatalf("chmod %s: %v", offender, err)
				}

				err := verifyCustody(root)
				if !errors.Is(err, ErrNoCustody) {
					t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
				}
				if !strings.Contains(err.Error(), offender) {
					t.Errorf("error %q does not name the offending path %s", err, offender)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not say it is writable by %s", err, tc.want)
				}
			})
		}
	}
}

// TestVerifyCustodyRefusesAnNFSv4ACL pins the check that a mode cannot make: an
// NFSv4 ACL can grant a named non-root user write access that the mode does not
// show, so its presence means this gate cannot see who may write and must decline.
//
// The xattr lister is substituted because no ordinary test process can mount a
// filesystem that exposes one. That is the branch's only seam, and the alternative
// is leaving the most consequential refusal in the file untested.
func TestVerifyCustodyRefusesAnNFSv4ACL(t *testing.T) {
	for _, attr := range aclXattrs {
		t.Run(attr, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			// A mode that passes every other check, which is the point: the ACL
			// is the only thing wrong, and a mode-only gate would wave it through.
			restore := stubListxattr(t, root, attr)
			defer restore()

			err := verifyCustody(root)
			if !errors.Is(err, ErrNoCustody) {
				t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
			}
			if !strings.Contains(err.Error(), attr) {
				t.Errorf("error %q does not name the access-control list %s", err, attr)
			}
		})
	}
}

// TestVerifyCustodyIgnoresAPOSIXACL pins the deliberate exemption, so a future
// tightening cannot quietly refuse the ordinary Linux volume. Under POSIX.1e the
// mode's group bits ARE the ACL mask, which caps every named entry, so the mode
// check already covers non-owner write and the ACL carries no hidden grant.
//
// The fixture is a real ACL rather than a stub: a named user with rwx under an r-x
// mask, which leaves the mode at 0755 and the user without write.
func TestVerifyCustodyIgnoresAPOSIXACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	switch err := setPOSIXACL(root, posixACLNamedUserUnderMask); {
	case err == nil:
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
		t.Skipf("this filesystem does not support POSIX ACLs (%v), so the exemption is untested here", err)
	default:
		// EINVAL and friends mean the kernel rejected THIS blob, which is a bug in
		// the fixture's encoding rather than a missing filesystem feature. Skipping
		// on it would quietly retire the one test that pins the exemption.
		t.Fatalf("the kernel rejected the fixture ACL (%v); the encoding in setPOSIXACL is wrong", err)
	}
	names, err := syscall.Listxattr(root, make([]byte, 1024))
	if err != nil || names == 0 {
		t.Skip("the POSIX ACL left no extended attribute, so there is nothing for the check to ignore")
	}
	if fi, statErr := os.Lstat(root); statErr != nil {
		t.Fatalf("lstat: %v", statErr)
	} else if fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("the fixture ACL widened the mode to %#o; it is meant to leave it at 0755, so this test would be asserting the wrong thing", fi.Mode().Perm())
	}

	if err := verifyCustody(root); err != nil {
		t.Fatalf("verifyCustody refused a directory whose POSIX ACL grants nothing its mode does not: %v", err)
	}
}

// TestVerifyCustodyRefusesANonDirectoryAndAMissingPath pins the two cheap
// structural refusals, which are the ones a caller hits from a typo rather than
// from an attack.
func TestVerifyCustodyRefusesANonDirectoryAndAMissingPath(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("a file in the chain", func(t *testing.T) {
		if err := verifyCustody(filepath.Join(file, "versions")); !errors.Is(err, ErrNoCustody) {
			t.Errorf("verifyCustody error = %v, want ErrNoCustody", err)
		}
	})
	t.Run("the root itself is a file", func(t *testing.T) {
		if err := verifyCustody(file); !errors.Is(err, ErrNoCustody) {
			t.Errorf("verifyCustody error = %v, want ErrNoCustody", err)
		}
	})
	t.Run("a path that does not exist", func(t *testing.T) {
		if err := verifyCustody(filepath.Join(base, "absent", "versions")); !errors.Is(err, ErrNoCustody) {
			t.Errorf("verifyCustody error = %v, want ErrNoCustody", err)
		}
	})
}

// TestVerifyCustodyJudgesTheResolvedChain pins that a symlink is resolved before
// the walk, so the directory a link lands in is what gets judged. Judging the link
// itself would be both wrong (a symlink's own mode grants nothing on Linux) and
// exploitable (a safe-looking link into a world-writable directory).
func TestVerifyCustodyJudgesTheResolvedChain(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaLink := filepath.Join(link, "pkg-versions")

	if err := verifyCustody(viaLink); err != nil {
		t.Fatalf("verifyCustody refused a private tree reached through a symlink: %v", err)
	}

	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatalf("chmod the link target: %v", err)
	}
	err := verifyCustody(viaLink)
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody once the link's TARGET is world-writable", err)
	}
	if !strings.Contains(err.Error(), real) {
		t.Errorf("error %q names the link rather than the resolved directory %s", err, real)
	}
}

// TestEnsureRefusesToInstallWithoutCustody is the integration statement: an install
// into a tree another principal can write does not happen, nothing is published, and
// the reason reaches the caller as a typed error rather than as a log line.
func TestEnsureRefusesToInstallWithoutCustody(t *testing.T) {
	env := newFakeEnv(t)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager()

	err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("Ensure error = %v, want ErrNoCustody", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published without custody", dirs)
	}
	if env.fetchCount() != 0 {
		t.Errorf("fetches = %d, want 0: custody is proved before a byte is downloaded", env.fetchCount())
	}
	if ready, why := m.Ready(); ready || why != ReasonInstalling {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonInstalling)
	}
}

// TestEnsureInstallsWithoutCustodyWhenTheCallerWaivesIt pins Untrusted as an
// informed waiver rather than a switch that turns the check off: the install
// proceeds, and the version this process installed becomes active.
func TestEnsureInstallsWithoutCustodyWhenTheCallerWaivesIt(t *testing.T) {
	env := newFakeEnv(t)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager(func(c *Config) { c.Untrusted = true })

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure with Untrusted set: %v", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Fatalf("Ready() = false (%s), want true", why)
	}
	if got := m.Path(); got != filepath.Join(env.versionDir(pinnedVersion), toolName) {
		t.Errorf("Path() = %q, want the freshly installed artifact", got)
	}
}

// TestEnsureWithoutCustodyIgnoresAVersionItDidNotInstall pins the other half of the
// waiver, and the reason the waiver is not simply "trust it anyway": a version
// directory that was already on the volume is NOT activated, because its sentinel is
// a plain file in a tree somebody else can write and is therefore forgeable.
func TestEnsureWithoutCustodyIgnoresAVersionItDidNotInstall(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager(func(c *Config) { c.Untrusted = true })
	env.onFetch = func(dst io.Writer) error { return errors.New("network is down") }

	err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure accepted a planted version directory in a tree without custody")
	}
	if ready, _ := m.Ready(); ready {
		t.Error("Ready() = true on a planted version this process did not install")
	}
}

// mustEval resolves path's symlinks or fails the test.
func mustEval(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", path, err)
	}
	return resolved
}

// stubListxattr makes the xattr lister report attr for target and nothing for any
// other path, and returns the restore. It is the seam for the NFSv4 branch, which
// no ordinary test filesystem can produce.
func stubListxattr(t *testing.T, target, attr string) func() {
	t.Helper()
	resolved := mustEval(t, target)
	old := listxattrNames
	listxattrNames = func(path string, dest []byte) (int, error) {
		if path != resolved {
			return 0, nil
		}
		names := append([]byte(attr), 0)
		if dest == nil {
			return len(names), nil
		}
		if len(dest) < len(names) {
			return 0, syscall.ERANGE
		}
		return copy(dest, names), nil
	}
	return func() { listxattrNames = old }
}

// POSIX ACL fixtures. The on-disk format is a version word followed by fixed-size
// entries, which is stable kernel ABI (uapi/linux/posix_acl_xattr.h), so building
// one by hand keeps this test free of a setfacl binary that many minimal images
// (including the container this suite runs in) do not ship.
const (
	posixACLVersion uint32 = 2
	aclTagUserObj   uint16 = 0x01
	aclTagUser      uint16 = 0x02
	aclTagGroupObj  uint16 = 0x04
	aclTagMask      uint16 = 0x10
	aclTagOther     uint16 = 0x20
	aclUndefinedID  uint32 = 0xFFFFFFFF
	aclPermRead     uint16 = 4
	aclPermWrite    uint16 = 2
	aclPermExecute  uint16 = 1
)

// posixACLNamedUserUnderMask grants a named user rwx while the mask allows only
// r-x. Under POSIX.1e semantics the mask is the ceiling, so the user ends up
// without write and the directory's mode stays 0755 — exactly the case that proves
// the mode is an upper bound for this dialect.
var posixACLNamedUserUnderMask = []posixACLEntry{
	{tag: aclTagUserObj, perm: aclPermRead | aclPermWrite | aclPermExecute, id: aclUndefinedID},
	{tag: aclTagUser, perm: aclPermRead | aclPermWrite | aclPermExecute, id: 1234},
	{tag: aclTagGroupObj, perm: aclPermRead | aclPermExecute, id: aclUndefinedID},
	{tag: aclTagMask, perm: aclPermRead | aclPermExecute, id: aclUndefinedID},
	{tag: aclTagOther, perm: aclPermRead | aclPermExecute, id: aclUndefinedID},
}

// posixACLEntry is one access-control entry in the xattr encoding.
type posixACLEntry struct {
	id   uint32
	tag  uint16
	perm uint16
}

// setPOSIXACL writes entries as path's POSIX access ACL.
func setPOSIXACL(path string, entries []posixACLEntry) error {
	blob := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range entries {
		blob = binary.LittleEndian.AppendUint16(blob, e.tag)
		blob = binary.LittleEndian.AppendUint16(blob, e.perm)
		blob = binary.LittleEndian.AppendUint32(blob, e.id)
	}
	return syscall.Setxattr(path, "system.posix_acl_access", blob, 0)
}

// TestVerifyCustodyRefusesAStickyInstallationRoot pins the difference between the
// leaf and its ancestors, which the first version of this check got wrong.
//
// Sticky restricts removal and renaming, never CREATE. On an ancestor that is
// enough, because what needs protecting there is our own directory entry. On the
// installation root it is not: anyone able to create entries inside it can plant a
// complete-looking version directory, and selection would accept it as installed.
// The end-to-end half is what makes the severity concrete — before the fix, Ensure
// activated a planted version with ZERO fetches.
func TestVerifyCustodyRefusesAStickyInstallationRoot(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.versionsRoot(), 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod the installation root sticky and world-writable: %v", err)
	}

	err := verifyCustody(env.versionsRoot())
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody for a sticky world-writable root", err)
	}
	if !strings.Contains(err.Error(), "sticky") {
		t.Errorf("error %q does not explain why the sticky bit is not enough here", err)
	}

	m := env.manager()
	_ = m.Ensure(context.Background())
	if ready, _ := m.Ready(); ready && env.fetchCount() == 0 {
		t.Error("Ensure activated a planted version through a sticky world-writable root without downloading anything")
	}
}

// TestVerifyCustodyRefusesAWritableDirectoryHoldingASymlinkOnThePath pins the
// second half of the chain rule. verifyCustody resolves symlinks, but every later
// operation in this package reaches the tree through the NAME (MkdirTemp,
// CreateTemp, OpenRoot, Rename, RemoveAll), so a component another principal can
// replace is a component that can be repointed after the verdict. Judging only the
// resolved chain let a 0777 directory holding the symlink go unexamined.
func TestVerifyCustodyRefusesAWritableDirectoryHoldingASymlinkOnThePath(t *testing.T) {
	base := t.TempDir()
	pub := filepath.Join(base, "pub")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(pub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(pub, "tools")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	viaLink := filepath.Join(pub, "tools", "pkg-versions")

	if err := verifyCustody(viaLink); err != nil {
		t.Fatalf("verifyCustody refused a private chain reached through a symlink: %v", err)
	}

	// The resolved target is untouched and still private; only the directory
	// HOLDING the link becomes writable, which is what repoints the name.
	if err := os.Chmod(pub, 0o777); err != nil {
		t.Fatalf("chmod the directory holding the symlink: %v", err)
	}
	err := verifyCustody(viaLink)
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody: the symlink's own directory is writable by everyone, so the name can be repointed", err)
	}
	if !strings.Contains(err.Error(), pub) {
		t.Errorf("error %q does not name %s, the directory that can repoint the path", err, pub)
	}
}

// TestVerifyCustodyRefusesAnUnreadableAttributeList pins the fail-closed direction.
// Reading the attribute list is part of establishing the precondition, so a list
// this process cannot read leaves it in the same position as finding an ACL it
// cannot evaluate. Only the "this filesystem has no extended attributes" answers
// are benign.
func TestVerifyCustodyRefusesAnUnreadableAttributeList(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	tests := map[string]struct {
		err     error
		wantErr bool
	}{
		"an I/O error":                {err: syscall.EIO, wantErr: true},
		"permission denied":           {err: syscall.EACCES, wantErr: true},
		"a list too big to read":      {err: syscall.E2BIG, wantErr: true},
		"no extended attributes":      {err: syscall.ENOTSUP},
		"no such attribute":           {err: syscall.ENODATA},
		"the call is not implemented": {err: syscall.ENOSYS},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			old := listxattrNames
			listxattrNames = func(string, []byte) (int, error) { return 0, tc.err }
			defer func() { listxattrNames = old }()

			err := verifyCustody(root)
			if tc.wantErr && !errors.Is(err, ErrNoCustody) {
				t.Fatalf("verifyCustody error = %v, want ErrNoCustody when listxattr answers %v", err, tc.err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("verifyCustody error = %v, want nil when listxattr answers %v (there is no ACL to hide anything)", err, tc.err)
			}
		})
	}
}

// TestVerifyCustodyRetriesAGrownAttributeList pins the whole ERANGE path: the retry
// uses the size the kernel reported, so a directory carrying many attributes cannot
// push an ACL name out of a fixed window, and a retry that itself fails refuses
// rather than concluding there is no ACL.
//
// The failure-after-ERANGE cases are listed explicitly because they are where the
// fail-open bug lived and where a mutant would hide: an error on the size query, a
// second ERANGE, or an error on the second fill.
func TestVerifyCustodyRetriesAGrownAttributeList(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	padding := make([]byte, 4096)
	for i := range padding {
		padding[i] = 'a'
	}
	names := append(append([]byte("user."), padding...), 0)
	names = append(names, []byte("system.nfs4_acl_xdr")...)
	names = append(names, 0)

	tests := map[string]struct {
		// after describes what the calls following the first ERANGE do.
		after   func(call int, dest []byte) (int, error)
		wantErr string
	}{
		"the retry succeeds and finds the ACL": {
			after: func(_ int, dest []byte) (int, error) {
				if dest == nil {
					return len(names), nil
				}
				return copy(dest, names), nil
			},
			wantErr: "system.nfs4_acl_xdr",
		},
		"the size query fails": {
			after:   func(int, []byte) (int, error) { return 0, syscall.EIO },
			wantErr: "input/output error",
		},
		"the size query reports nothing": {
			after: func(_ int, dest []byte) (int, error) {
				if dest == nil {
					return 0, nil
				}
				return 0, nil
			},
			wantErr: "after refusing",
		},
		"the retry is short again": {
			after: func(_ int, dest []byte) (int, error) {
				if dest == nil {
					return len(names), nil
				}
				return 0, syscall.ERANGE
			},
			wantErr: "numerical result out of range",
		},
		"the retry fails": {
			after: func(_ int, dest []byte) (int, error) {
				if dest == nil {
					return len(names), nil
				}
				return 0, syscall.E2BIG
			},
			wantErr: "argument list too long",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			call := 0
			old := listxattrNames
			listxattrNames = func(_ string, dest []byte) (int, error) {
				call++
				if call == 1 {
					return 0, syscall.ERANGE
				}
				return tc.after(call, dest)
			}
			defer func() { listxattrNames = old }()

			err := verifyCustody(root)
			if !errors.Is(err, ErrNoCustody) {
				t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestEnsureDeletesNothingInATreeItRefuses pins that the read-only precondition is
// actually read-only across the whole operation, not only inside its own function. The
// legacy purge, the partial sweep, the retention prune, the convenience link and the
// state record are all mutations under Root, and running any of them inside a tree the
// library then refuses would assert exactly the authority the refusal disclaims.
//
// Both branches that regressed once are covered: a tree where the versions directory
// already exists, and one where it does not — the latter because a clean verdict used
// to be recorded for an absent directory, which let the purge sweep Root on the
// strength of a verdict about nothing.
func TestEnsureDeletesNothingInATreeItRefuses(t *testing.T) {
	t.Run("the versions directory exists", func(t *testing.T) {
		env := newFakeEnv(t)
		partial := env.placePartial("1.0.0")
		if err := os.Chmod(env.root, 0o777); err != nil {
			t.Fatalf("chmod the install root: %v", err)
		}
		m := env.manager()

		if err := m.Ensure(context.Background()); !errors.Is(err, ErrNoCustody) {
			t.Fatalf("Ensure error = %v, want ErrNoCustody", err)
		}
		if !exists(partial) {
			t.Errorf("Ensure deleted %s inside a tree it refused to install into", partial)
		}
		if exists(env.statePath()) {
			t.Errorf("Ensure wrote %s inside a tree it refused to install into", env.statePath())
		}
	})

	t.Run("the versions directory does not exist yet", func(t *testing.T) {
		env := newFakeEnv(t)
		legacy := filepath.Join(env.root, "bin", toolName)
		if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := writeFakeBinary(legacy, "0.9.0"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		if err := os.Chmod(env.root, 0o777); err != nil {
			t.Fatalf("chmod the install root: %v", err)
		}
		m := env.manager(func(c *Config) {
			c.LinkDir = "bin"
			c.Purge = &Purge{Names: []string{toolName}}
		})

		if err := m.Ensure(context.Background()); !errors.Is(err, ErrNoCustody) {
			t.Fatalf("Ensure error = %v, want ErrNoCustody", err)
		}
		if !exists(legacy) {
			t.Errorf("the legacy purge deleted %s before any verdict about the tree existed", legacy)
		}
		if exists(env.statePath()) {
			t.Errorf("Ensure wrote %s inside a tree it refused to install into", env.statePath())
		}
	})
}

// TestSelectActiveExcludesAVersionWithAWritableArtifact pins the check custody of
// the TREE cannot make. Directory write permission governs creating, removing and
// renaming entries — not writing to the contents of an entry that already exists —
// so a group- or other-writable artifact inside a directory nobody else can add to
// is still a binary this package executes and another principal can rewrite.
//
// The version probe does not cover this: a rewritten binary can print whatever
// version its directory name claims.
func TestSelectActiveExcludesAVersionWithAWritableArtifact(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	if err := os.Chmod(filepath.Join(dir, toolName), 0o777); err != nil {
		t.Fatalf("chmod the artifact: %v", err)
	}
	m := env.manager()
	m.checkCustody()

	if _, ok := m.selectActive(context.Background()); ok {
		t.Fatal("selectActive accepted a version whose primary artifact is writable by another principal")
	}
}

// TestMoveArtifactRefusesToPublishAWritableArtifact pins the same rule at the other
// end. An in-archive installer chooses its own modes, and the rename into the
// version directory is the last point at which what it chose can be refused:
// publish moves this inode into place and a rename cannot change a mode.
func TestMoveArtifactRefusesToPublishAWritableArtifact(t *testing.T) {
	env := newFakeEnv(t)
	env.produces = map[string]string{toolName: pinnedVersion, toolSidecar: pinnedVersion, toolExtra: pinnedVersion}
	env.wideArtifacts = []string{toolName}
	m := env.manager()

	err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure published an artifact the installer left writable by another principal")
	}
	if !strings.Contains(err.Error(), "writable by another principal") {
		t.Errorf("Ensure error = %v, want one naming the writable artifact", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published", dirs)
	}
}

// TestUntrustedAloneForcesDistrustOnACleanTree isolates the flag from the
// measurement, which is the one thing the other Untrusted tests cannot do: they make
// the root world-writable first, so the measured verdict would produce the same
// outcome and removing the flag's branch would leave them green.
//
// Here custody is intact and the flag is the only reason the planted directory is
// refused. That contract predates the measurement and has now silently regressed
// once, which is why it gets a test of its own.
func TestUntrustedAloneForcesDistrustOnACleanTree(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	m := env.manager(func(c *Config) { c.Untrusted = true })
	m.checkCustody()

	if verdict := m.custodyVerdict(); verdict != nil {
		t.Fatalf("the fixture tree does not have custody (%v), so this test would not isolate the flag", verdict)
	}
	if _, ok := m.selectActive(context.Background()); ok {
		t.Fatal("selectActive accepted a pre-existing version directory although Untrusted is set on a tree WITH custody")
	}

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1: Untrusted must force a digest-verified reinstall even on a private tree", env.fetchCount())
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true after the verified reinstall", why)
	}
}

// TestSelectActiveExcludesAVersionWithAWritableOptionalArtifact pins the half of the
// artifact rule that the first fix missed. An optional artifact is executed too:
// PathEntry puts the whole version directory at the front of PATH, and a
// multi-binary release's primary artifact resolves its sidecars from there by bare
// name, so a rewritable optional artifact is as much a root-executed binary as a
// required one.
func TestSelectActiveExcludesAVersionWithAWritableOptionalArtifact(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion, toolName, toolSidecar, toolExtra)
	optional := filepath.Join(dir, toolExtra)
	if _, err := os.Lstat(optional); err != nil {
		t.Fatalf("the fixture did not place the optional artifact %s: %v", toolExtra, err)
	}
	if err := os.Chmod(optional, 0o777); err != nil {
		t.Fatalf("chmod the optional artifact: %v", err)
	}
	m := env.manager()
	m.checkCustody()

	if _, ok := m.selectActive(context.Background()); ok {
		t.Fatal("selectActive accepted a version whose optional artifact is writable by another principal")
	}
}

// TestPruneKeepsAUsablePredecessorWhenANewerVersionIsUnactivatable pins retention
// against the interaction the artifact rule introduced. A version excluded for
// holding a rewritable artifact must not spend the retain slot the usable
// predecessor needs: doing so deletes the fallback and leaves the recovery
// guarantee resting on a directory selection already refuses.
func TestPruneKeepsAUsablePredecessorWhenANewerVersionIsUnactivatable(t *testing.T) {
	env := newFakeEnv(t)
	wide := env.placeVersion("2.0.0")
	env.placeVersion("1.0.0")
	if err := os.Chmod(filepath.Join(wide, toolName), 0o777); err != nil {
		t.Fatalf("chmod the artifact of 2.0.0: %v", err)
	}
	m := env.manager(func(c *Config) { c.Retain = 1 })

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !exists(env.versionDir("1.0.0")) {
		t.Error("pruning deleted the usable predecessor 1.0.0 while retaining 2.0.0, which selection refuses to activate")
	}
	if !exists(wide) {
		t.Error("pruning deleted 2.0.0, which it should leave exactly as found for the operator to look at")
	}
}

// TestVerifyCustodyRefusesAForeignSymlinkReachedThroughAnotherLink pins the sticky
// rule against the shape that reopened it. parentSticky used to be read off the
// component's own Lstat mode, and a symlink's mode is 0777 with no sticky bit on every
// Linux system, so an intermediate symlink reported "not sticky" whatever it pointed
// at and the ownership demand never fired for the component below it.
//
// Named directly, the foreign link inside the sticky directory was refused; reached
// through a private link to that same directory, it was accepted.
func TestVerifyCustodyRefusesAForeignSymlinkReachedThroughAnotherLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("planting a foreign-owned symlink needs root")
	}
	base := t.TempDir()
	shared := filepath.Join(base, "shared")
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// A world-writable sticky directory, i.e. /tmp's shape, which the ancestor rule
	// deliberately accepts.
	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod sticky: %v", err)
	}
	hop := filepath.Join(shared, "hop")
	if err := os.Symlink(real, hop); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Owned by somebody else, which inside a sticky directory means only THEY can
	// remove or replace it.
	if err := os.Lchown(hop, 12345, 12345); err != nil {
		t.Skipf("cannot chown a symlink here (%v), so the foreign-link case is untested", err)
	}

	t.Run("named directly", func(t *testing.T) {
		err := verifyCustody(filepath.Join(hop, "pkg-versions"))
		if !errors.Is(err, ErrNoCustody) {
			t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
		}
		if !strings.Contains(err.Error(), "12345") {
			t.Errorf("error %q does not name the uid that can repoint the link", err)
		}
	})

	t.Run("reached through a private link to the sticky directory", func(t *testing.T) {
		via := filepath.Join(base, "via")
		if err := os.Symlink(shared, via); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		err := verifyCustody(filepath.Join(via, "hop", "pkg-versions"))
		if !errors.Is(err, ErrNoCustody) {
			t.Fatalf("verifyCustody error = %v, want ErrNoCustody: the same foreign link is on the path, one indirection further", err)
		}
	})
}

// TestFinishDoesNotMutateATreeWhoseVerdictFlippedMidOperation pins the last two writes
// under the tree: the retention prune, which deletes version directories, and the
// convenience link.
//
// The reachable path is narrow and worth spelling out, because the first attempt at this
// test asserted it from a configuration where the gate was open. Custody is clean when
// Ensure starts, so selection succeeds; the operator re-permissions the volume while the
// operation is in flight (driven here from the probe seam, which is where selection
// crosses into the outside world); install then re-proves custody, refuses, and finish
// runs with a failed verdict and NO waiver. That is the one state in which
// mayMutateTree is false with a selection in hand.
func TestFinishDoesNotMutateATreeWhoseVerdictFlippedMidOperation(t *testing.T) {
	env := newFakeEnv(t)
	// Three complete versions, none of them the pin, so selection succeeds on the
	// newest and 0.8.0 is outside the retained set and would be pruned.
	env.placeVersion("1.0.0")
	env.placeVersion("0.9.0")
	env.placeVersion("0.8.0")

	var once bool
	env.onProbe = func(bin string) ([]byte, error) {
		if !once {
			once = true
			// The volume becomes shared while the operation is in flight.
			if err := os.Chmod(env.root, 0o777); err != nil {
				t.Fatalf("chmod the install root: %v", err)
			}
		}
		return env.probeAnswer(bin)
	}
	m := env.manager(func(c *Config) { c.LinkDir = "bin" })

	err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("Ensure error = %v, want ErrNoCustody: the install must refuse once the verdict flips", err)
	}
	if m.custodyVerdict() == nil {
		t.Fatal("the fixture did not flip the verdict, so this test proves nothing")
	}
	if !exists(env.versionDir("0.8.0")) {
		t.Error("the retention prune deleted a version directory in a tree the same operation refused to mutate")
	}
	if exists(filepath.Join(env.root, "bin", toolName)) {
		t.Error("the convenience link was published inside a tree the same operation refused to mutate")
	}
}

// TestSelectActiveRefusesEvenItsOwnInstallWithoutCustodyOrAWaiver pins the security
// decision that regressed twice and took three review rounds to settle, and it is the
// only test that isolates it: every other custody test sets Config.Untrusted, which
// takes the waiver branch and would stay green if this rule were reverted.
//
// What the installed set proves is that THIS process published a version from a verified
// archive at some earlier instant, not that the bytes are unchanged now. Once the tree is
// writable, the directory check, the artifact check and the probe are three path-based
// operations with gaps between them, and the failed verdict is precisely the fact that
// makes that race possible. So readiness is withheld rather than granted on a claim the
// library cannot make.
func TestSelectActiveRefusesEvenItsOwnInstallWithoutCustodyOrAWaiver(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	// A clean install first, so the installed set holds the pin.
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Fatalf("Ready() = false (%s) after a clean install", why)
	}

	// Now the volume becomes shared, and the caller has NOT waived the precondition.
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m.checkCustody()
	if m.custodyVerdict() == nil {
		t.Fatal("the fixture did not degrade custody, so this test proves nothing")
	}

	if sel, ok := m.selectActive(context.Background()); ok {
		t.Errorf("selectActive accepted %q on the strength of the installed set alone, with no custody and no waiver", sel.version)
	}
	if _, err := m.Rescan(context.Background()); !errors.Is(err, ErrNoCustody) {
		t.Errorf("Rescan error = %v, want ErrNoCustody so the operator is pointed at the volume", err)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}
