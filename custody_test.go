package pinstall

import (
	"context"
	"encoding/base64"
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
	if err := verifyCustody(dir, trustedWriters{}); err != nil {
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
	const strangerGID = 65500
	tests := map[string]struct {
		mode  os.FileMode
		chgrp bool
		want  string
	}{
		"group writable, by a group that is not root": {mode: 0o775, chgrp: true, want: "gid 65500"},
		"other writable": {mode: 0o757, want: "everyone"},
		// Both bits set names the GROUP, not everyone: writersOf enumerates the group
		// first and firstStranger stops at the first writer the caller has not
		// accounted for. The group is pinned to a stranger here rather than left as
		// whatever gid the test process happens to carry, because the root group is
		// trusted — so as root this case would report everyone and as anyone else the
		// group, and the assertion would be describing the environment.
		"both writable, the group reported first":       {mode: 0o777, chgrp: true, want: "gid 65500"},
		"group write only, by a group that is not root": {mode: 0o720, chgrp: true, want: "gid 65500"},
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
				if tc.chgrp {
					if err := os.Chown(offender, -1, strangerGID); err != nil {
						t.Skipf("cannot hand %s to gid %d (%v), so a group grant to a stranger is untestable here", offender, strangerGID, err)
					}
				}
				if err := os.Chmod(offender, tc.mode); err != nil {
					t.Fatalf("chmod %s: %v", offender, err)
				}

				err := verifyCustody(root, trustedWriters{})
				if !errors.Is(err, ErrNoCustody) {
					t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
				}
				if !strings.Contains(err.Error(), offender) {
					t.Errorf("error %q does not name the offending path %s", err, offender)
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not name the writer (%s)", err, tc.want)
				}
			})
		}
	}
}

// TestVerifyCustodyAcceptsAGroupOnlyRootCanUse pins the precision the parsed writer set
// buys, and it is a case the earlier mode-only rule refused for no reason: a directory at
// 0775 owned by root:root is writable by the root group, whose only member is root, which
// this check already trusts. Refusing it made the gate look arbitrary and taught operators
// to reach for the waiver.
func TestVerifyCustodyAcceptsAGroupOnlyRootCanUse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs to run as root for the root group to be the fixture's group")
	}
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := verifyCustody(root, trustedWriters{}); err != nil {
		t.Fatalf("verifyCustody refused a directory writable only by the root group: %v", err)
	}
}

// TestVerifyCustodyAcceptsADeclaredGroup pins the group half of the declaration, which is
// the weaker of the two claims because a group grant reaches every current and future
// member.
func TestVerifyCustodyAcceptsADeclaredGroup(t *testing.T) {
	const strangerGID = 65500
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chown(root, -1, strangerGID); err != nil {
		t.Skipf("cannot hand the fixture to gid %d (%v)", strangerGID, err)
	}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := verifyCustody(root, trustedWriters{}); !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody before the group is declared", err)
	}
	if err := verifyCustody(root, trustedWriters{gids: []int{strangerGID}}); err != nil {
		t.Fatalf("verifyCustody refused a group the caller declared: %v", err)
	}
}

// TestVerifyCustodyNeverTrustsEveryone pins the one identity that cannot be declared. A
// grant to everyone names no identity, so accepting it would be turning the check off
// while pretending to narrow it — which is what InstallWithoutCustody is for, honestly.
//
// The mode grants everyone write and the group NOTHING, so everyone is the only writer in
// the set and the assertion cannot be satisfied by some other stranger reported first. At
// 0777 the group is enumerated ahead of everyone, and the root group is trusted while an
// ordinary one is not, so that mode would report everyone as root and a gid as anyone
// else — an assertion about the environment rather than about the rule.
func TestVerifyCustodyNeverTrustsEveryone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o707); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Every identity this process could possibly name, including its own group, so the
	// refusal is not an artifact of an incomplete list.
	trust := trustedWriters{
		uids: []int{0, 1, 2, 3000, os.Geteuid()},
		gids: []int{0, 1, 2, 568, os.Getgid()},
	}
	err := verifyCustody(root, trust)
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody: no list of identities can cover everyone", err)
	}
	if !strings.Contains(err.Error(), "everyone") {
		t.Errorf("error %q does not name everyone as the writer", err)
	}
}

// TestVerifyCustodyEvaluatesAnNFSv4ACL pins the check a mode cannot make. An NFSv4 ACL
// can grant a named non-root user write access the mode does not show, so the list is
// PARSED and its grants are judged like any other writer — refused when the identity is a
// stranger, accepted when the caller has declared it.
//
// The attribute is served through a substituted reader because no ordinary test process
// can mount a filesystem that produces one. The blob itself is a real list, captured from
// a ZFS nfsv4 dataset (see acl_golden_test.go), so what is faked is the delivery and not
// the content.
func TestVerifyCustodyEvaluatesAnNFSv4ACL(t *testing.T) {
	sample := nfs4Samples["root-owned tools directory, mode 0750"]
	blob, err := base64.StdEncoding.DecodeString(sample.b64)
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}

	tests := map[string]struct {
		trust   trustedWriters
		wantErr bool
		wantIn  string
	}{
		"nothing declared": {
			trust: trustedWriters{}, wantErr: true, wantIn: "uid 3000",
		},
		"the wrong uid declared": {
			trust: trustedWriters{uids: []int{4242}}, wantErr: true, wantIn: "uid 3000",
		},
		"the writer declared": {
			trust: trustedWriters{uids: []int{3000}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			defer serveACL(t, root, xattrNFS4XDR, blob)()

			err := verifyCustody(root, tc.trust)
			if tc.wantErr {
				if !errors.Is(err, ErrNoCustody) {
					t.Fatalf("verifyCustody error = %v, want ErrNoCustody", err)
				}
				if !strings.Contains(err.Error(), tc.wantIn) {
					t.Errorf("error %q does not name the writer (%s)", err, tc.wantIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyCustody refused a tree whose only extra writer the caller declared: %v", err)
			}
		})
	}
}

// TestVerifyCustodyRefusesAnUnreadableACL pins the fail-closed direction. Reading the list
// is part of establishing the precondition, so an attribute this process cannot read leaves
// it in the same position as finding a grant it cannot accept. Only the answers that
// genuinely mean "this filesystem has no extended attributes" are benign.
func TestVerifyCustodyRefusesAnUnreadableACL(t *testing.T) {
	tests := map[string]struct {
		err     error
		wantErr bool
	}{
		"an I/O error":                {err: syscall.EIO, wantErr: true},
		"permission denied":           {err: syscall.EACCES, wantErr: true},
		"a value too big to read":     {err: syscall.E2BIG, wantErr: true},
		"no such attribute":           {err: syscall.ENODATA},
		"no extended attributes":      {err: syscall.ENOTSUP},
		"the call is not implemented": {err: syscall.ENOSYS},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			old := getxattrFn
			getxattrFn = func(string, string, []byte) (int, error) { return 0, tc.err }
			defer func() { getxattrFn = old }()

			err := verifyCustody(root, trustedWriters{})
			switch {
			case tc.wantErr && !errors.Is(err, ErrNoCustody):
				t.Fatalf("verifyCustody error = %v, want ErrNoCustody when getxattr answers %v", err, tc.err)
			case tc.wantErr && !errors.Is(err, ErrACLUnreadable):
				t.Errorf("verifyCustody error = %v, want it to wrap ErrACLUnreadable", err)
			case !tc.wantErr && err != nil:
				t.Fatalf("verifyCustody error = %v, want nil when getxattr answers %v", err, tc.err)
			}
		})
	}
}

// TestVerifyCustodyRefusesAMalformedACL pins that bytes which are not a well-formed list
// refuse rather than parse to an empty writer set. Under-reporting writers is precisely how
// this check would wave through the tree it exists to refuse.
func TestVerifyCustodyRefusesAMalformedACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	defer serveACL(t, root, xattrNFS4XDR, []byte("not an acl"))()

	err := verifyCustody(root, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) || !errors.Is(err, ErrACLUnreadable) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody wrapping ErrACLUnreadable", err)
	}
}

// TestVerifyCustodyAcceptsAPOSIXACLThatGrantsNothing pins the dialect that needs no
// declaration: under POSIX.1e the mask caps every named entry, so a list granting a user
// rwx under an r-x mask grants no write and the tree stays private. The fixture is a real
// ACL the kernel enforces, not a parsed blob.
func TestVerifyCustodyAcceptsAPOSIXACLThatGrantsNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	switch err := setPOSIXACL(root, posixACLNamedUserUnderMask); {
	case err == nil:
	case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
		t.Skipf("this filesystem does not support POSIX ACLs (%v)", err)
	default:
		t.Fatalf("the kernel rejected the fixture ACL (%v); the encoding in encodePOSIXACL is wrong", err)
	}
	if fi, err := os.Lstat(root); err != nil {
		t.Fatalf("lstat: %v", err)
	} else if fi.Mode().Perm()&0o022 != 0 {
		t.Fatalf("the fixture widened the mode to %#o; it is meant to leave it at 0755", fi.Mode().Perm())
	}

	if err := verifyCustody(root, trustedWriters{}); err != nil {
		t.Fatalf("verifyCustody refused a directory whose POSIX ACL grants no write: %v", err)
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
		if err := verifyCustody(filepath.Join(file, "versions"), trustedWriters{}); !errors.Is(err, ErrNoCustody) {
			t.Errorf("verifyCustody error = %v, want ErrNoCustody", err)
		}
	})
	t.Run("the root itself is a file", func(t *testing.T) {
		if err := verifyCustody(file, trustedWriters{}); !errors.Is(err, ErrNoCustody) {
			t.Errorf("verifyCustody error = %v, want ErrNoCustody", err)
		}
	})
	t.Run("a path that does not exist", func(t *testing.T) {
		if err := verifyCustody(filepath.Join(base, "absent", "versions"), trustedWriters{}); !errors.Is(err, ErrNoCustody) {
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

	if err := verifyCustody(viaLink, trustedWriters{}); err != nil {
		t.Fatalf("verifyCustody refused a private tree reached through a symlink: %v", err)
	}

	if err := os.Chmod(real, 0o777); err != nil {
		t.Fatalf("chmod the link target: %v", err)
	}
	err := verifyCustody(viaLink, trustedWriters{})
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
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })

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
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })
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

// serveACL makes the attribute reader return blob as target's attr, and nothing for any
// other path or name. It is the seam for the NFSv4 dialect, which no ordinary test
// filesystem can produce.
func serveACL(t *testing.T, target, attr string, blob []byte) func() {
	t.Helper()
	resolved := mustEval(t, target)
	old := getxattrFn
	getxattrFn = func(path, name string, dest []byte) (int, error) {
		if path != resolved || name != attr {
			return 0, syscall.ENODATA
		}
		if dest == nil {
			return len(blob), nil
		}
		if len(dest) < len(blob) {
			return 0, syscall.ERANGE
		}
		return copy(dest, blob), nil
	}
	return func() { getxattrFn = old }
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

	err := verifyCustody(env.versionsRoot(), trustedWriters{})
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

	if err := verifyCustody(viaLink, trustedWriters{}); err != nil {
		t.Fatalf("verifyCustody refused a private chain reached through a symlink: %v", err)
	}

	// The resolved target is untouched and still private; only the directory
	// HOLDING the link becomes writable, which is what repoints the name.
	if err := os.Chmod(pub, 0o777); err != nil {
		t.Fatalf("chmod the directory holding the symlink: %v", err)
	}
	err := verifyCustody(viaLink, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody: the symlink's own directory is writable by everyone, so the name can be repointed", err)
	}
	if !strings.Contains(err.Error(), pub) {
		t.Errorf("error %q does not name %s, the directory that can repoint the path", err, pub)
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
		err := verifyCustody(filepath.Join(hop, "pkg-versions"), trustedWriters{})
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
		err := verifyCustody(filepath.Join(via, "hop", "pkg-versions"), trustedWriters{})
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

// TestWideArtifactCoversUndeclaredEntries pins that the check is about the DIRECTORY's
// contents, not about the names this deployment happens to declare. PathEntry leads PATH
// with the whole version directory and a multi-binary release resolves its sidecars from
// there by bare name, so an undeclared executable in a restored tree is reachable too.
func TestWideArtifactCoversUndeclaredEntries(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	m := env.manager()
	if wide := m.wideArtifact(dir); wide != "" {
		t.Fatalf("wideArtifact = %q on a clean directory, want \"\"", wide)
	}

	stray := filepath.Join(dir, "not-declared-anywhere")
	if err := writeFakeBinary(stray, pinnedVersion); err != nil {
		t.Fatalf("writeFakeBinary: %v", err)
	}
	if err := os.Chmod(stray, 0o777); err != nil {
		t.Fatalf("chmod the undeclared entry: %v", err)
	}
	if wide := m.wideArtifact(dir); wide != "not-declared-anywhere" {
		t.Errorf("wideArtifact = %q, want the undeclared entry: it sits on PATH like every other file there", wide)
	}
}

// TestWorldWritableStickyFailsClosed pins the direction of the one fact that decides
// whether a symlink must be owned by us. An unreadable answer must count as sticky: the
// unknown can then only ADD the ownership demand, where the opposite default let a
// transient stat failure on the parent retire it silently.
func TestWorldWritableStickyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if got := worldWritableSticky(dir); got {
		t.Errorf("worldWritableSticky(%s) = true on a private directory", dir)
	}
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if got := worldWritableSticky(dir); !got {
		t.Errorf("worldWritableSticky(%s) = false on a world-writable sticky directory", dir)
	}
	if got := worldWritableSticky(filepath.Join(dir, "does-not-exist")); !got {
		t.Error("worldWritableSticky = false for a path it could not stat, which retires the ownership demand instead of adding it")
	}
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got := worldWritableSticky(file); got {
		t.Error("worldWritableSticky = true for a regular file, which is not a directory anything can be created in")
	}
}

// TestRetentionNeverExecutesAVersionSelectionRefuses pins the ordering inside
// usableAsFallback. probeVersion EXECUTES the artifact, so asking it about a directory
// selection has refused would run a binary this manager declined to activate, as its own
// uid, on the shared volume Config.Untrusted describes. Retention is a disk-hygiene
// decision and must not become an execution path selection would not take.
func TestRetentionNeverExecutesAVersionSelectionRefuses(t *testing.T) {
	env := newFakeEnv(t)
	planted := env.placeVersion("9.9.9")
	m := env.manager(func(c *Config) { c.Untrusted = true })
	m.checkCustody()

	if m.trusted("9.9.9") {
		t.Fatal("the fixture is wrong: the planted version must be untrusted for this test to mean anything")
	}
	if m.usableAsFallback(context.Background(), "9.9.9") {
		t.Error("usableAsFallback accepted a version selection refuses")
	}
	if got := env.countCalls("probe " + filepath.Join(planted, toolName)); got != 0 {
		t.Errorf("the planted artifact was executed %d times by retention, after selection had refused it", got)
	}
}

// TestUnavailableReportsTheWaiverCauseNotTheWaivedVerdict pins that a failed verdict is
// only reported as the cause when it is what BLOCKED activation. Under the waiver it is
// the accepted state, and reporting it would send an operator to fix permissions they
// deliberately chose while hiding the real reason.
func TestUnavailableReportsTheWaiverCauseNotTheWaivedVerdict(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	env.onFetch = func(io.Writer) error { return errors.New("network is down") }
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })

	err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure succeeded although the planted version is untrusted and the fetch fails")
	}
	if errors.Is(err, ErrNoCustody) {
		t.Errorf("Ensure error = %v, want the install failure: the caller waived custody, so the verdict is not what blocked this", err)
	}
}

// TestDeclaringTheAdminKeepsCustodyAndAvoidsAReinstall is the case the whole
// TrustedUIDs/TrustedGIDs mechanism exists for, and it is the one an operator will hit.
//
// A volume is reached over NFS by an administrator who already holds root on the host.
// That account can write the installation tree, so custody legitimately fails and the
// library legitimately refuses — it can see the grant and cannot see that the grantee is
// already privileged. Declaring the identity restores custody, which is the point:
// InstallWithoutCustody would also get the install running, but it treats the tree as
// unmanageable and so re-downloads the archive on EVERY start, because nothing already on
// disk may be activated. Both halves are asserted here, because the reinstall cost is the
// thing that makes the blunt instrument unusable in practice.
func TestDeclaringTheAdminKeepsCustodyAndAvoidsAReinstall(t *testing.T) {
	const adminUID = 65501

	// A fixture whose tree is writable by another uid: the closest a test can get to the
	// NFS-admin shape without a second account to run as.
	setup := func(t *testing.T) *fakeEnv {
		t.Helper()
		env := newFakeEnv(t)
		if err := os.Chown(env.root, -1, 65500); err != nil {
			t.Skipf("cannot hand the fixture to another group (%v)", err)
		}
		if err := os.Chmod(env.root, 0o770); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		return env
	}

	t.Run("refused when nothing is declared", func(t *testing.T) {
		env := setup(t)
		m := env.manager()
		if err := m.Ensure(context.Background()); !errors.Is(err, ErrNoCustody) {
			t.Fatalf("Ensure error = %v, want ErrNoCustody", err)
		}
		if !strings.Contains(m.custodyVerdict().Error(), "gid 65500") {
			t.Errorf("verdict %q does not name the writer", m.custodyVerdict())
		}
	})

	t.Run("declared: custody holds and a restart reuses the install", func(t *testing.T) {
		env := setup(t)
		trust := func(c *Config) { c.TrustedGIDs = []int{65500}; c.TrustedUIDs = []int{adminUID} }

		m := env.manager(trust)
		if err := m.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure with the writer declared: %v", err)
		}
		if m.custodyVerdict() != nil {
			t.Fatalf("custody still fails (%v); declaring the writer must restore it, not waive it", m.custodyVerdict())
		}
		if ready, why := m.Ready(); !ready {
			t.Fatalf("Ready() = false (%s)", why)
		}
		first := env.fetchCount()

		// A fresh Manager over the same on-disk tree: a container restart.
		m2 := env.manager(trust)
		if err := m2.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure after a restart: %v", err)
		}
		if got := env.fetchCount(); got != first {
			t.Errorf("fetches went from %d to %d across a restart; declaring the writer must not cost a reinstall", first, got)
		}
	})

	t.Run("waived instead: every restart re-downloads", func(t *testing.T) {
		env := setup(t)
		waive := func(c *Config) { c.InstallWithoutCustody = true }

		m := env.manager(waive)
		if err := m.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure with the waiver: %v", err)
		}
		first := env.fetchCount()

		m2 := env.manager(waive)
		if err := m2.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure after a restart: %v", err)
		}
		if got := env.fetchCount(); got == first {
			t.Errorf("fetches stayed at %d across a restart under the waiver; the restriction on activating a pre-existing version is what makes the precise knob worth having", got)
		}
	})
}

// TestInstallWithoutCustodyStillRefusesAPlantedVersion pins that the blunt waiver is not a
// way to trust the tree. It permits installing there and it re-authorises the library's own
// housekeeping, but a version directory this process did not publish is still refused,
// because a completion sentinel in a tree somebody else can write is forgeable.
func TestInstallWithoutCustodyStillRefusesAPlantedVersion(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })
	m.checkCustody()

	if _, ok := m.selectActive(context.Background()); ok {
		t.Error("selectActive accepted a planted version under InstallWithoutCustody")
	}
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1: the planted version must be replaced by a verified install", env.fetchCount())
	}
}
