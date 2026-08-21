package pinstall

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
		"an I/O error":            {err: syscall.EIO, wantErr: true},
		"permission denied":       {err: syscall.EACCES, wantErr: true},
		"a value too big to read": {err: syscall.E2BIG, wantErr: true},
		"no such attribute":       {err: syscall.ENODATA},
		"no extended attributes":  {err: syscall.ENOTSUP},
		// ENOSYS is not an absence and used to be read as one. It means the getxattr call
		// did not happen -- an old kernel, or far more likely a seccomp filter denying the
		// syscall -- so it says nothing about the object. Treating it as "no list" let a
		// sandbox that blocks getxattr produce a CLEAN verdict for a tree an
		// access-control list grants a stranger write to, which is a sandbox making this
		// check weaker rather than stricter.
		"the call was denied or is unimplemented": {err: syscall.ENOSYS, wantErr: true},
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

// TestVerifyCustodyJudgesTheDirectoryHoldingAnIntermediateSymlink pins the hops in the
// MIDDLE of a chain, which had no judge at all while the resolution was delegated whole to
// filepath.EvalSymlinks: the path as written was walked, the path it fully resolved to was
// walked, and the directories holding every link in between were visited by EvalSymlinks
// internally and then forgotten.
//
// The shape is an ordinary release layout — /opt/app -> /srv/current -> /mnt/data/app-1 —
// needs no ACL and reproduces on ext4. Only the directory holding the middle link is
// widened here, so both endpoints stay private and neither of the two chains the old shape
// walked contains an offender. That is not the accepted TOCTOU: at the instant of the
// verdict, anyone who can write that directory repoints the middle link, and the next
// MkdirTemp, OpenRoot or Rename lands in a tree of their choosing.
func TestVerifyCustodyJudgesTheDirectoryHoldingAnIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	priv := filepath.Join(base, "priv")
	mid := filepath.Join(base, "mid")
	target := filepath.Join(base, "target")
	for _, dir := range []string{priv, mid, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", dir, err)
		}
	}
	link := filepath.Join(mid, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entry := filepath.Join(priv, "entry")
	if err := os.Symlink(link, entry); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := verifyCustody(entry, trustedWriters{}); err != nil {
		t.Fatalf("verifyCustody refused a private two-hop chain: %v", err)
	}

	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatalf("chmod the directory holding the middle link: %v", err)
	}
	err := verifyCustody(entry, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody: everyone can write %s, which holds the link the chain goes through", err, mid)
	}
	if !strings.Contains(err.Error(), mid) {
		t.Errorf("error %q does not name %s, the directory that can repoint the middle of the chain", err, mid)
	}
	if !strings.Contains(err.Error(), "0777") {
		t.Errorf("error %q does not quote the offending mode", err)
	}

	// The witness that this is the same directory the walk already knew how to refuse, so
	// what was missing was the judge and not the rule.
	if err := verifyCustody(mid, trustedWriters{}); !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody(%s) = %v, want ErrNoCustody when named directly", mid, err)
	}
}

// TestVerifyCustodyRefusesASymlinkCycle pins the bound on the resolution. A cycle has no
// resolved path, so there is nothing to judge and nothing to be told about: an error is the
// only answer that is not a clean verdict about a tree nobody can reach. Resolving the chain
// one link at a time is what makes the bound this walk's own responsibility rather than
// EvalSymlinks's.
func TestVerifyCustodyRefusesASymlinkCycle(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "a")
	b := filepath.Join(base, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	err := verifyCustody(a, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody for a chain that does not resolve", err)
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("error %v does not carry ELOOP, which is what an operator will recognise this as", err)
	}
}

// TestVerifyCustodyFollowsAsManyLinksAsTheKernelWould pins where the resolution bound
// sits. The bound mirrors SYMLOOP_MAX, so a chain the kernel would resolve has to be one
// this walk resolves too: refusing one link earlier would refuse a tree open(2) reaches
// perfectly well, and the refusal is an install outage rather than a diagnosis.
//
// Each pass expands ONE link, and the pass after the last expansion is the one that judges
// where the tree actually lives, so a chain of exactly the bound needs one more pass than
// it has links.
func TestVerifyCustodyFollowsAsManyLinksAsTheKernelWould(t *testing.T) {
	// chain links a run of symlinks ending at a private directory and returns the head.
	chain := func(t *testing.T, links int) string {
		t.Helper()
		base := t.TempDir()
		target := filepath.Join(base, "installed")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("Mkdir(%s): %v", target, err)
		}
		next := target
		for i := links - 1; i >= 0; i-- {
			link := filepath.Join(base, fmt.Sprintf("hop%02d", i))
			if err := os.Symlink(next, link); err != nil {
				t.Fatalf("Symlink(%s -> %s): %v", link, next, err)
			}
			next = link
		}
		return next
	}

	t.Run("a chain at the bound resolves", func(t *testing.T) {
		if err := verifyCustodyChain(chain(t, maxSymlinkHops), trustedWriters{}, true); err != nil {
			t.Errorf("verifyCustodyChain over %d links = %v, want nil: the kernel follows a chain this long",
				maxSymlinkHops, err)
		}
	})

	t.Run("a chain past the bound is refused", func(t *testing.T) {
		err := verifyCustodyChain(chain(t, maxSymlinkHops+1), trustedWriters{}, true)
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("verifyCustodyChain over %d links = %v, want an ELOOP refusal", maxSymlinkHops+1, err)
		}
	})
}

// TestVerifyCustodyRefusesAForeignSymlinkInAStickyDirectoryWidenedOnlyByItsACL is the
// confirmed fail-open pair, whose two halves differ in nothing but the access-control list.
// A sticky directory at 1777 holding a stranger's symlink is refused; the same directory at
// 1755, wide only because an EVERYONE@ entry grants write, used to be accepted — because the
// fact deciding whether the link must be ours was read off the mode alone, on the very
// filesystems this package parses lists for BECAUSE the mode is lossy.
func TestVerifyCustodyRefusesAForeignSymlinkInAStickyDirectoryWidenedOnlyByItsACL(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("planting a foreign-owned symlink needs root; sharedSticky's own test is the unprivileged witness for the rule")
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
	// Sticky, and 0755: the MODE says nobody else can create an entry here.
	if err := os.Chmod(shared, os.ModeSticky|0o755); err != nil {
		t.Fatalf("chmod sticky: %v", err)
	}
	hop := filepath.Join(shared, "hop")
	if err := os.Symlink(real, hop); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := os.Lchown(hop, 12345, 12345); err != nil {
		t.Skipf("cannot chown a symlink here (%v), so the foreign-link case is untested", err)
	}
	// The list is what actually makes the directory shared, and it is the only difference
	// from the 1777 case the suite already pins.
	everyone := buildNFS4ACL(nfs4TypeAllow, 0, nfs4WhoIsSpecial, nfs4WriteData, nfs4WhoEveryone)
	defer serveACL(t, shared, xattrNFS4XDR, everyone)()

	err := verifyCustody(filepath.Join(hop, "pkg-versions"), trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody: the list lets anyone create entries in %s, so uid 12345's link there can be repointed", err, shared)
	}
	if !strings.Contains(err.Error(), "12345") {
		t.Errorf("error %q does not name the uid that can repoint the link", err)
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

	err := m.Ensure(t.Context())
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

	if err := m.Ensure(t.Context()); err != nil {
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

	err := m.Ensure(t.Context())
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
	_ = m.Ensure(t.Context())
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

		if err := m.Ensure(t.Context()); !errors.Is(err, ErrNoCustody) {
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

		if err := m.Ensure(t.Context()); !errors.Is(err, ErrNoCustody) {
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

	if _, ok := m.selectActive(t.Context()); ok {
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

	err := m.Ensure(t.Context())
	if err == nil {
		t.Fatal("Ensure published an artifact the installer left writable by another principal")
	}
	// "writable by" rather than the identity: the writer set enumerates the group first
	// and gid 0 is trusted, so a root container names everyone where an unprivileged CI
	// runner names the process's own gid. Both are the same refusal.
	if !strings.Contains(err.Error(), "writable by") || !strings.Contains(err.Error(), toolName) {
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
	if _, ok := m.selectActive(t.Context()); ok {
		t.Fatal("selectActive accepted a pre-existing version directory although Untrusted is set on a tree WITH custody")
	}

	if err := m.Ensure(t.Context()); err != nil {
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

	if _, ok := m.selectActive(t.Context()); ok {
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

	if err := m.Ensure(t.Context()); err != nil {
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

	err := m.Ensure(t.Context())
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
	if err := m.Ensure(t.Context()); err != nil {
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

	if sel, ok := m.selectActive(t.Context()); ok {
		t.Errorf("selectActive accepted %q on the strength of the installed set alone, with no custody and no waiver", sel.version)
	}
	if _, err := m.Rescan(t.Context()); !errors.Is(err, ErrNoCustody) {
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
	if entry, reason := m.wideArtifact(dir); entry != "" {
		t.Fatalf("wideArtifact = (%q, %q) on a clean directory, want no offender", entry, reason)
	}

	stray := filepath.Join(dir, "not-declared-anywhere")
	if err := writeFakeBinary(stray, pinnedVersion); err != nil {
		t.Fatalf("writeFakeBinary: %v", err)
	}
	if err := os.Chmod(stray, 0o777); err != nil {
		t.Fatalf("chmod the undeclared entry: %v", err)
	}
	entry, reason := m.wideArtifact(dir)
	if entry != "not-declared-anywhere" {
		t.Errorf("wideArtifact = %q, want the undeclared entry: it sits on PATH like every other file there", entry)
	}
	if !strings.Contains(reason, "writable by") {
		t.Errorf("wideArtifact reason = %q, want one naming the identity that can write it", reason)
	}
}

// TestSharedStickyAsksTheListAndFailsClosed pins the one fact that decides whether a
// symlink must be owned by us, in both of the directions it can be wrong.
//
// The mode is not the answer. On the filesystems this package parses lists for, a directory
// at 1755 carrying an EVERYONE@ write entry is one anybody can create entries in, so a
// stranger's symlink inside it can be repointed after the verdict — and a mode-only rule
// reports 0755 and nothing else, which is how the confirmed fail-open pair differed only in
// its ACL. A grant the caller has DECLARED is not a stranger's, here as everywhere else in
// the walk.
//
// And an answer that could not be obtained must count as shared: the unknown can then only
// ADD the ownership demand, where the opposite default let a transient stat failure on the
// parent retire it silently.
func TestSharedStickyAsksTheListAndFailsClosed(t *testing.T) {
	const stranger = 4242
	euid := os.Geteuid()

	// A directory of its own inside the temp root, so its mode is the fixture's rather
	// than whatever t.TempDir chose.
	newDir := func(t *testing.T, mode os.FileMode) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		return dir
	}

	t.Run("a private directory", func(t *testing.T) {
		dir := newDir(t, 0o755)
		if sharedSticky(dir, euid, trustedWriters{}) {
			t.Errorf("sharedSticky(%s) = true on a private directory", dir)
		}
	})

	t.Run("sticky and world-writable by mode", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o777)
		if !sharedSticky(dir, euid, trustedWriters{}) {
			t.Errorf("sharedSticky(%s) = false on a sticky directory everyone can write", dir)
		}
	})

	t.Run("sticky at 1755, wide only by its access-control list", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger))()

		if !sharedSticky(dir, euid, trustedWriters{}) {
			t.Errorf("sharedSticky(%s) = false although its list lets uid %d write: the mode is a lossy projection of the list, and the loss runs the unsafe way",
				dir, stranger)
		}
		if sharedSticky(dir, euid, trustedWriters{uids: []int{stranger}}) {
			t.Errorf("sharedSticky(%s) = true although the caller declared uid %d, which is not a stranger anywhere else in this walk",
				dir, stranger)
		}
	})

	t.Run("sticky at 1755, with a list that grants no write", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		const readData uint32 = 0x00000001
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, readData, stranger))()

		if sharedSticky(dir, euid, trustedWriters{}) {
			t.Errorf("sharedSticky(%s) = true although the list grants uid %d nothing but read", dir, stranger)
		}
	})

	t.Run("a list that could not be read", func(t *testing.T) {
		dir := newDir(t, os.ModeSticky|0o755)
		old := getxattrFn
		getxattrFn = func(string, string, []byte) (int, error) { return 0, syscall.EIO }
		defer func() { getxattrFn = old }()

		if !sharedSticky(dir, euid, trustedWriters{}) {
			t.Error("sharedSticky = false for a sticky directory whose list it could not read, which retires the ownership demand instead of adding it")
		}
	})

	t.Run("a path it could not stat", func(t *testing.T) {
		dir := newDir(t, 0o755)
		if !sharedSticky(filepath.Join(dir, "does-not-exist"), euid, trustedWriters{}) {
			t.Error("sharedSticky = false for a path it could not stat, which retires the ownership demand instead of adding it")
		}
	})

	t.Run("a wide list on a directory that is not sticky", func(t *testing.T) {
		// Outside the scope of this fact: without the sticky bit the walk refuses such a
		// component outright, and this answer only decides whether a symlink INSIDE it
		// must be ours.
		dir := newDir(t, 0o755)
		defer serveACL(t, dir, xattrNFS4XDR, buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger))()

		if sharedSticky(dir, euid, trustedWriters{}) {
			t.Errorf("sharedSticky(%s) = true on a directory with no sticky bit", dir)
		}
	})

	t.Run("a regular file", func(t *testing.T) {
		dir := newDir(t, 0o755)
		file := filepath.Join(dir, "a-file")
		if err := os.WriteFile(file, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if sharedSticky(file, euid, trustedWriters{}) {
			t.Error("sharedSticky = true for a regular file, which is not a directory anything can be created in")
		}
	})
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

	if mayActivate, _ := m.trusted("9.9.9"); mayActivate {
		t.Fatal("the fixture is wrong: the planted version must be untrusted for this test to mean anything")
	}
	if m.usableAsFallback(t.Context(), "9.9.9") {
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

	err := m.Ensure(t.Context())
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
		if err := m.Ensure(t.Context()); !errors.Is(err, ErrNoCustody) {
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
		if err := m.Ensure(t.Context()); err != nil {
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
		if err := m2.Ensure(t.Context()); err != nil {
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
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure with the waiver: %v", err)
		}
		first := env.fetchCount()

		m2 := env.manager(waive)
		if err := m2.Ensure(t.Context()); err != nil {
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

	if _, ok := m.selectActive(t.Context()); ok {
		t.Error("selectActive accepted a planted version under InstallWithoutCustody")
	}
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1: the planted version must be replaced by a verified install", env.fetchCount())
	}
}

// TestVerifyCustodyRefusesThenAcceptsTheProcessOwnGroup is the UNPRIVILEGED witness for
// the group half of the declaration, and for group-write refusal itself. Both properties
// are otherwise covered only by tests that chown a fixture to a pinned stranger gid, which
// no unprivileged process can do -- so on CI, where the gate actually runs, every one of
// those skips and nothing fails if Config.TrustedGIDs stops reaching the writer set at all.
//
// The fixture's group is this process's own primary gid, which needs no chown and which
// trustedWriters treats as a stranger for the same reason it treats any other ordinary
// group as one: a group grant reaches every current and future member. The root group is
// the exception the rule is built around -- its only member is root, which the check
// already trusts -- so as root there is no stranger here to refuse and the test says so
// instead of asserting whatever the environment happens to be.
func TestVerifyCustodyRefusesThenAcceptsTheProcessOwnGroup(t *testing.T) {
	gid := os.Getgid()
	if gid == 0 {
		t.Skip("the root group is always trusted, so it cannot stand in for a stranger here; the pinned-gid tests cover this shape where privilege exists")
	}
	root := filepath.Join(t.TempDir(), "pkg-versions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(root, 0o775); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := verifyCustody(root, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody error = %v, want ErrNoCustody for a group-writable root", err)
	}
	if want := fmt.Sprintf("gid %d", gid); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name the writing group (%s)", err, want)
	}
	if err := verifyCustody(root, trustedWriters{gids: []int{gid}}); err != nil {
		t.Fatalf("verifyCustody refused a group the caller declared: %v", err)
	}
}

// TestNewWiresTheDeclaredIdentities pins that Config.TrustedUIDs and Config.TrustedGIDs
// actually reach the Manager's writer set. It exists because the end-to-end tests for that
// wiring all need privilege, so replacing the whole assignment in New with an empty
// trustedWriters left the unprivileged suite green -- both knobs disconnected, nothing
// failing. This asserts on the resolved set instead of on a filesystem it would have to
// chown, so it runs and gates at any privilege.
func TestNewWiresTheDeclaredIdentities(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) {
		c.TrustedUIDs = []int{3000}
		c.TrustedGIDs = []int{65500}
	})

	if !slices.Equal(m.trust.uids, []int{3000}) || !slices.Equal(m.trust.gids, []int{65500}) {
		t.Fatalf("m.trust = %+v, want the declared identities", m.trust)
	}
	if !m.trust.allows(principal{kind: principalGroup, id: 65500}, os.Geteuid()) {
		t.Error("a declared gid is not allowed, so the declaration did not reach the writer set")
	}
	if !m.trust.allows(principal{kind: principalUser, id: 3000}, os.Geteuid()) {
		t.Error("a declared uid is not allowed, so the declaration did not reach the writer set")
	}
	if m.trust.allows(principal{kind: principalEveryone}, os.Geteuid()) {
		t.Error("everyone was allowed, which no declaration may ever do")
	}
}

// TestVerifyCustodyRefusesAStickyAncestorWhoseACLGivesItAway pins the one condition the
// sticky exemption depends on and cannot itself check.
//
// The exemption is sound as an argument about the CURRENT mode: sticky restricts removal
// and renaming to each entry's owner, so a principal who can create files beside ours
// cannot rename ours away, which is what makes /tmp a usable place to root an install. But
// it is an argument about a mode and an ownership that a sufficiently privileged ACE can
// change. WRITE_OWNER lets its holder take the directory, after which chmod is theirs and
// the sticky bit goes; WRITE_ACL lets them grant themselves the rest; DELETE_CHILD is the
// sticky rule itself written into the list, which RFC 7530 lets the list decide. The kernel
// enforcing check_sticky() today says nothing about a rule the attacker can rewrite tomorrow.
//
// So the sticky branch reads the grants that would retire the sticky rule itself and nothing
// else: an ordinary write grant on a sticky ancestor stays exempt, which is the whole point
// of the exemption.
func TestVerifyCustodyRefusesAStickyAncestorWhoseACLGivesItAway(t *testing.T) {
	const stranger = 4242

	tests := map[string]struct {
		mask      uint32
		wantRefus bool
	}{
		"write access, which sticky genuinely contains": {mask: nfs4WriteData},
		"append, likewise": {mask: nfs4AppendData},
		// DELETE_CHILD is not something sticky contains, it is the sticky rule stated in
		// the list -- and RFC 7530 makes the list the access decision, leaving sticky as
		// the fallback for when it does not decide. On the 1777 ancestor this exemption
		// exists for, the mode already lets its holder create the replacement, so being
		// able to remove a component this walk has just judged is a complete substitution
		// of the tree probeVersion then executes as root.
		"delete child, which the list is entitled to grant over sticky": {mask: nfs4DeleteChild, wantRefus: true},
		"take ownership, which removes the sticky bit":                  {mask: nfs4WriteOwner, wantRefus: true},
		"rewrite the list, which grants the rest":                       {mask: nfs4WriteACL, wantRefus: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "tools")
			root := filepath.Join(parent, "pkg-versions")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			// A world-writable sticky ancestor: the /tmp shape the exemption exists for.
			// os.ModeSticky is a FileMode bit of its own, not octal 0o1000 -- passing
			// 0o1777 sets plain 0777, which the walk then refuses as world-writable
			// before the sticky branch is ever reached.
			if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			blob := buildNFS4ACL(nfs4TypeAllow, 0, 0, tc.mask, stranger)
			defer serveACL(t, parent, xattrNFS4XDR, blob)()

			err := verifyCustody(root, trustedWriters{})
			switch {
			case tc.wantRefus && !errors.Is(err, ErrNoCustody):
				t.Errorf("verifyCustody = %v, want ErrNoCustody: the list lets uid %d remove the sticky protection the exemption relies on",
					err, stranger)
			case !tc.wantRefus && err != nil:
				t.Errorf("verifyCustody = %v, want nil: a plain write grant on a sticky ancestor is what the exemption exists to allow", err)
			}
			if tc.wantRefus && err != nil && !strings.Contains(err.Error(), "sticky") {
				t.Errorf("error %q does not explain that the sticky bit was what failed", err)
			}
		})
	}
}

// TestAllowsOwnerJudgesTheOwningIdentity is the only coverage the ownership rule has. No
// filesystem fixture can express it: root is always allowed, and every directory an
// unprivileged test can create belongs to the runner, which is also always allowed. So the
// rule is asserted directly, which is possible at any privilege because both identities
// are parameters rather than ambient state.
func TestAllowsOwnerJudgesTheOwningIdentity(t *testing.T) {
	const euid, admin, stranger = 1000, 3000, 4242

	tests := map[string]struct {
		owner int
		trust trustedWriters
		want  bool
	}{
		"this process":                     {owner: euid, want: true},
		"root":                             {owner: 0, want: true},
		"a stranger":                       {owner: stranger, want: false},
		"a stranger the caller declared":   {owner: admin, trust: trustedWriters{uids: []int{admin}}, want: true},
		"a stranger declared as a GROUP":   {owner: admin, trust: trustedWriters{gids: []int{admin}}, want: false},
		"a stranger beside a declared one": {owner: stranger, trust: trustedWriters{uids: []int{admin}}, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.trust.allowsOwner(tc.owner, euid); got != tc.want {
				t.Errorf("allowsOwner(owner=%d, euid=%d) with %+v = %v, want %v", tc.owner, euid, tc.trust, got, tc.want)
			}
		})
	}
}

// serveACLWhere is serveACL for a path the test cannot name in advance, such as the staged
// version directory, whose parent carries a random suffix.
func serveACLWhere(t *testing.T, match func(path string) bool, attr string, blob []byte) func() {
	t.Helper()
	old := getxattrFn
	getxattrFn = func(path, name string, dest []byte) (int, error) {
		if name != attr || !match(path) {
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

// TestPublishRefusesAVersionDirectoryTheFilesystemWidened pins the other half of the
// publish gate. moveArtifact judges each artifact it renames in; the version DIRECTORY and
// the sentinel are the two entries publish creates itself, and nothing judged them.
//
// The trigger is not an injected value, it is the filesystem storing a wider mode than
// MkdirAll asked for -- an inherited NFSv4 ACE on OpenZFS does exactly that, which is the
// filesystem family this library parses those lists for. The consequence is worse than a
// refusal, because the install SUCCEEDS: selection then refuses the directory forever, so
// every start re-fetches the archive and reports ErrNoVersion with the complete directory
// sitting right there. Config.MaxAttempts exists to stop that loop and cannot, because
// each attempt succeeds.
//
// The ACL is served onto the staged directory rather than chmod-ed, because that is the
// real shape AND it needs no privilege, so this gates on CI too.
func TestPublishRefusesAVersionDirectoryTheFilesystemWidened(t *testing.T) {
	const stranger = 4242

	env := newFakeEnv(t)
	env.produces = map[string]string{toolName: pinnedVersion, toolSidecar: pinnedVersion, toolExtra: pinnedVersion}
	m := env.manager()

	// The staged version directory is the only path whose base is "v".
	wide := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	defer serveACLWhere(t, func(path string) bool { return filepath.Base(path) == "v" }, xattrNFS4XDR, wide)()

	err := m.Ensure(t.Context())
	if err == nil {
		t.Fatal("Ensure published a version directory another principal can modify, which selection will refuse for the life of the volume")
	}
	if !strings.Contains(err.Error(), "version directory") {
		t.Errorf("Ensure error = %v, want one naming the version directory as the thing refused", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published", dirs)
	}
}

// TestVerifyCustodyWalksThroughASymlinkToTheResolvedTree pins that the walk judges the path
// it RESOLVES to and not only the path as written, without needing any privilege: the
// refusal comes from the list the seam serves on the resolved directory.
//
// It deliberately does NOT witness checkSymlink -- that guard is about who owns the LINK,
// and this passes with it disabled, because the resolved walk catches the target on its own.
// checkSymlink's witness is the unit test below it.
func TestVerifyCustodyWalksThroughASymlinkToTheResolvedTree(t *testing.T) {
	const stranger = 4242

	base := t.TempDir()
	real := filepath.Join(base, "elsewhere")
	link := filepath.Join(base, "tools")
	root := filepath.Join(link, "pkg-versions")
	if err := os.MkdirAll(filepath.Join(real, "pkg-versions"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// The list sits on the RESOLVED directory, which is the object the walk would miss if
	// it only judged the path as written.
	wide := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	defer serveACL(t, real, xattrNFS4XDR, wide)()

	err := verifyCustody(root, trustedWriters{})
	if !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustody = %v, want ErrNoCustody: the resolved directory is writable by uid %d", err, stranger)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("uid %d", stranger)) {
		t.Errorf("error %q does not name the identity the resolved directory grants write to", err)
	}
}

// TestCheckSymlinkJudgesWhoOwnsTheLink is checkSymlink's only witness, and it has to be a
// unit test: the guard fires on a symlink OWNED BY A STRANGER inside a sticky directory
// others can write, and handing a link to another uid needs CAP_CHOWN. So the end-to-end
// coverage all skips on the unprivileged runner CI uses, and the whole function body could
// be replaced with `return nil` while the suite stayed green -- the same shape that hid the
// disconnected trusted-writer knobs.
//
// Both identities are parameters, so the predicate itself gates at any privilege. Whether the
// parent IS such a directory is [sharedSticky]'s question, and its own test covers the mode
// and the access-control list that answer it.
//
// The rule is narrow on purpose. A stranger-owned symlink only matters where that stranger
// could have PLANTED it, which is a directory they can create in; anywhere else the link is
// the operator's own arrangement and its target is judged on its own merits by the walk.
func TestCheckSymlinkJudgesWhoOwnsTheLink(t *testing.T) {
	const euid, admin, stranger = 1000, 3000, 4242

	tests := map[string]struct {
		owner        int
		parentShared bool
		trust        trustedWriters
		wantRefusal  bool
	}{
		"a stranger's link in a sticky directory others can write": {owner: stranger, parentShared: true, wantRefusal: true},
		"the same link where the parent is not shared":             {owner: stranger},
		"our own link, shared parent":                              {owner: euid, parentShared: true},
		"root's link, shared parent":                               {owner: 0, parentShared: true},
		"a declared identity's link, shared parent":                {owner: admin, parentShared: true, trust: trustedWriters{uids: []int{admin}}},
		"an undeclared stranger beside a declared one":             {owner: stranger, parentShared: true, trust: trustedWriters{uids: []int{admin}}, wantRefusal: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkSymlink("/some/link", tc.owner, euid, tc.parentShared, tc.trust)
			switch {
			case tc.wantRefusal && !errors.Is(err, ErrNoCustody):
				t.Errorf("checkSymlink(owner=%d, shared=%v) = %v, want ErrNoCustody: that user can repoint the link",
					tc.owner, tc.parentShared, err)
			case !tc.wantRefusal && err != nil:
				t.Errorf("checkSymlink(owner=%d, shared=%v) = %v, want nil", tc.owner, tc.parentShared, err)
			}
		})
	}
}

// TestPublishRefusesAWidenedSentinel covers the half of the publish gate the
// directory-level test does not reach. wideArtifact answers on the DIRECTORY first, so a
// wide directory short-circuits before the entry loop runs at all — which left the sentinel,
// one of the two entries publish creates, unpinned by the very test added to pin it.
//
// The sentinel is the entry a wide mode matters most for: it is the file that says "this
// directory is complete", so a principal who can rewrite it can mark a half-populated
// directory ready.
func TestPublishRefusesAWidenedSentinel(t *testing.T) {
	const stranger = 4242

	env := newFakeEnv(t)
	env.produces = map[string]string{toolName: pinnedVersion, toolSidecar: pinnedVersion, toolExtra: pinnedVersion}
	m := env.manager()

	// Served on the sentinel alone, so the directory itself passes and the entry loop is
	// what has to catch this.
	wide := buildNFS4ACL(nfs4TypeAllow, 0, 0, nfs4WriteData, stranger)
	defer serveACLWhere(t, func(path string) bool {
		return filepath.Base(path) == sentinelName
	}, xattrNFS4XDR, wide)()

	err := m.Ensure(t.Context())
	if err == nil {
		t.Fatal("Ensure published a version directory whose completion sentinel another principal can rewrite")
	}
	if !errors.Is(err, ErrNoCustody) {
		t.Errorf("Ensure error = %v, want it to wrap ErrNoCustody so a caller can tell this from a fetch failure", err)
	}
	if !strings.Contains(err.Error(), sentinelName) {
		t.Errorf("error %q does not name the sentinel as the entry refused", err)
	}
	if dirs := env.versionDirs(); len(dirs) != 0 {
		t.Errorf("installation root holds %v, want nothing published", dirs)
	}
}

// TestAllowsTrustsGroupZeroWithoutPrivilege is the unprivileged witness for the gid-0 rule.
// The end-to-end test for it (TestVerifyCustodyAcceptsAGroupOnlyRootCanUse) skips unless the
// runner is root, so the acceptance was pinned only where privilege exists — the same
// root-only-green shape that let the trusted-writer knobs be disconnected with CI green.
//
// The rule is deliberate and its limit is stated on allows() itself: group-0 membership is
// not root's privilege, so a host whose root GROUP has members is outside what this check
// covers. It is kept because refusing gid 0 would refuse a single root:root 0775 ancestor
// and turn an ordinary tree into a total install outage.
func TestAllowsTrustsGroupZeroWithoutPrivilege(t *testing.T) {
	const euid = 1000
	trust := trustedWriters{}

	if !trust.allows(principal{kind: principalGroup, id: 0}, euid) {
		t.Error("group 0 is not trusted; refusing it turns a root:root 0775 ancestor into an install outage")
	}
	// The neighbouring rules, so a mutant that widens this one is caught here too.
	if trust.allows(principal{kind: principalGroup, id: 1}, euid) {
		t.Error("group 1 is trusted, but only group 0 is")
	}
	if trust.allows(principal{kind: principalEveryone}, euid) {
		t.Error("everyone is trusted, which nothing may ever make true")
	}
}

// TestARefusalNamesTheTrustKnobsOnlyWhileTheyAreUnused pins the hint's two directions.
// An operator who has not heard of Config.TrustedUIDs needs the refusal to name it; one
// who has clearly used it needs the message not to repeat the suggestion, because the
// identity they are being told about is then the real problem rather than a knob they
// have not found yet.
//
// The fixture grants EVERYONE write and the owning group nothing, so the stranger the
// walk names is "everyone" whatever uid or gid the runner has, and everyone is one
// identity these knobs can never declare.
func TestARefusalNamesTheTrustKnobsOnlyWhileTheyAreUnused(t *testing.T) {
	const knob = "Config.TrustedUIDs"
	dir := filepath.Join(t.TempDir(), toolName+versionsSuffix)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir(%s): %v", dir, err)
	}
	if err := os.Chmod(dir, 0o707); err != nil {
		t.Fatalf("Chmod(%s): %v", dir, err)
	}

	tests := map[string]struct {
		trust    trustedWriters
		wantHint bool
	}{
		"nothing declared":    {wantHint: true},
		"uids declared":       {trust: trustedWriters{uids: []int{4242}}},
		"gids declared":       {trust: trustedWriters{gids: []int{4242}}},
		"both kinds declared": {trust: trustedWriters{uids: []int{4242}, gids: []int{4242}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := verifyCustody(dir, tc.trust)
			if !errors.Is(err, ErrNoCustody) {
				t.Fatalf("verifyCustody(%+v) = %v, want ErrNoCustody: everyone can write this directory", tc.trust, err)
			}
			switch got := strings.Contains(err.Error(), knob); {
			case tc.wantHint && !got:
				t.Errorf("error %q does not name %s, the knob that answers a refusal like this", err, knob)
			case !tc.wantHint && got:
				t.Errorf("error %q names %s to a caller that has already used it", err, knob)
			}
		})
	}
}

// TestAnUncontrolledTreeIsWarnedAbout pins the diagnostic half of the custody verdict.
// A refusal changes what the manager will ACTIVATE and nothing about what any call
// returns, so this line is the only place an operator learns that a completion sentinel
// in this tree has stopped being evidence — and a clean tree must not emit it, or the
// warning stops meaning anything.
func TestAnUncontrolledTreeIsWarnedAbout(t *testing.T) {
	logs := captureLogs(t)

	// 0707 grants everyone write and the owning group nothing, so the tree is shared
	// whatever uid or gid the runner has.
	env := newFakeEnv(t)
	if err := os.MkdirAll(env.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", env.versionsRoot(), err)
	}
	if err := os.Chmod(env.versionsRoot(), 0o707); err != nil {
		t.Fatalf("Chmod(%s): %v", env.versionsRoot(), err)
	}
	shared := env.manager()
	shared.checkCustody()

	if err := shared.custodyVerdict(); err == nil {
		t.Fatal("custodyVerdict is nil, so this fixture is not the shared tree the test is about")
	}
	got := logs.at(slog.LevelWarn, "root")
	if len(got) != 1 || got[0].attrs["root"] != env.versionsRoot() {
		t.Fatalf("Warn records naming the installation root = %v, want one naming %s", got, env.versionsRoot())
	}

	clean := newFakeEnv(t)
	if err := os.MkdirAll(clean.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", clean.versionsRoot(), err)
	}
	private := clean.manager()
	private.checkCustody()

	if err := private.custodyVerdict(); err != nil {
		t.Fatalf("custodyVerdict = %v, want nil on a private tree", err)
	}
	if got := logs.at(slog.LevelWarn, "root"); len(got) != 1 {
		t.Errorf("Warn records naming the installation root = %v, want the count unchanged by a tree this process controls", got)
	}
}

// TestFirstStartOnAStickySharedParentRunsTheOneShotPurge pins the judgement the walk
// cannot read off a component's POSITION, and the start it used to cost.
//
// checkCustody judges the nearest EXISTING directory when the installation root does not
// exist yet, so on the first start that directory is the last component of the chain while
// being an ANCESTOR of the tree. Deciding leaf-ness positionally therefore held it to the
// installation-root rule and withheld the sticky exemption it is entitled to — and a
// /tmp-shaped (1777) shared parent is exactly the shape that exemption exists for. The
// consequence is not cosmetic: mayMutateTree was false on the one start where the one-shot
// legacy purge can still run, and a later start, once the versions directory existed,
// passed the very same directory.
//
// No privilege is needed and none is assumed: 1777 grants EVERYONE write, so the strict
// judgement refuses it whatever gid the runner has.
func TestFirstStartOnAStickySharedParentRunsTheOneShotPurge(t *testing.T) {
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	legacyArtifact := filepath.Join(env.root, ".toolkit-installed")
	// The /tmp shape. Sticky is what makes such a directory usable as an ancestor at all.
	if err := os.Chmod(env.root, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod the shared parent: %v", err)
	}
	if exists(env.versionsRoot()) {
		t.Fatal("the installation root already exists, so this fixture is not a first start and the test proves nothing")
	}

	// The two rules, on the same directory, distinguished only by which question is being
	// asked of it. This is the whole of the fix, and it fails in both directions if the
	// strictness goes back to being positional.
	if err := verifyCustodyChain(env.root, trustedWriters{}, true); !errors.Is(err, ErrNoCustody) {
		t.Fatalf("verifyCustodyChain(judgeLeafStrictly=true) = %v, want ErrNoCustody: the installation root is never exempted, sticky or not", err)
	}
	if err := verifyCustodyChain(env.root, trustedWriters{}, false); err != nil {
		t.Fatalf("verifyCustodyChain(judgeLeafStrictly=false) = %v, want nil: a sticky ancestor others can write is exempt from the write question", err)
	}

	m := env.manager(func(c *Config) { c.Purge = testPurge() })
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if err := m.custodyVerdict(); err != nil {
		t.Errorf("custodyVerdict = %v, want nil: the first start judged its sticky ancestor by the installation-root rule", err)
	}
	if !m.mayMutateTree() {
		t.Error("mayMutateTree is false, so the one-shot purge is skipped on the only start that can run it")
	}
	if exists(legacyArtifact) {
		t.Error("the legacy artifact survived the first start, so the one-shot purge did not run")
	}
	if !exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the purge completion marker was not recorded, so the sweep never completed on the first start")
	}
}
