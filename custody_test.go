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
	if err := setPOSIXACL(root, posixACLNamedUserUnderMask); err != nil {
		t.Skipf("this filesystem does not accept a POSIX ACL (%v), so the exemption is untested here", err)
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
