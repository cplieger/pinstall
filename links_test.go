package pinstall

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// A release that ships its binaries straight from the archive and drops four of its five
// between two versions, with the consumer's declared set shrinking to match.
const (
	shrinkWideVersion   = "2.37.1"
	shrinkNarrowVersion = "3.0.0"
	shrinkArtifactDir   = "toolkit/bin"
	toolAlias           = "tk"
	toolAliasChat       = "tkchat"
)

// shrinkRelease is the primary profile with no installer, so each archive alone decides
// which artifacts a version holds.
func shrinkRelease() Release {
	r := toolRelease()
	r.Installer = nil
	r.ArtifactDir = shrinkArtifactDir
	return r
}

// shrinkArchive holds one executable per name under the profile's ArtifactDir, each
// reporting version.
func shrinkArchive(t *testing.T, version string, names ...string) []byte {
	t.Helper()
	entries := make(map[string]zipEntry, len(names))
	for _, n := range names {
		entries[shrinkArtifactDir+"/"+n] = zipEntry{body: fakeBinaryBody(version), mode: 0o755}
	}
	return buildZip(t, entries)
}

// newShrinkEnv is a volume on which the five-binary release has been activated, with
// LinkDir created and plant run before that first install.
func newShrinkEnv(t *testing.T, plant func(env *fakeEnv, linkDir string)) *fakeEnv {
	t.Helper()
	wide := shrinkArchive(t, shrinkWideVersion, toolName, toolSidecar, toolExtra, toolAlias, toolAliasChat)
	env := newEnv(t, shrinkRelease(), wide, []string{toolSidecar}, []string{toolExtra, toolAlias, toolAliasChat})
	linkDir := filepath.Join(env.root, testLinkDir)
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", linkDir, err)
	}
	if plant != nil {
		plant(env, linkDir)
	}
	if err := env.manager(func(c *Config) { c.Version = shrinkWideVersion }).Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure %s: %v", shrinkWideVersion, err)
	}
	return env
}

// shrinkTo points env at the one-binary release, declared with nothing beyond the
// primary, and runs Ensure on it.
func shrinkTo(t *testing.T, env *fakeEnv) error {
	t.Helper()
	env.archive = shrinkArchive(t, shrinkNarrowVersion, toolName)
	env.digest = digestOf(env.archive)
	env.require, env.optional = nil, nil
	return env.manager(func(c *Config) { c.Version = shrinkNarrowVersion }).Ensure(t.Context())
}

// TestConvenienceLinksRetractWhatADroppedReleaseNoLongerShips pins retraction on
// ownership rather than on the names the current configuration declares. A consumer
// moving to a release that ships one binary instead of five also stops declaring the
// other four, and the links this manager published for them must still go: left in place
// they keep resolving into the predecessor and dangle once retention prunes it. An entry
// this manager did not create, at one of those names or anywhere else, is never touched.
func TestConvenienceLinksRetractWhatADroppedReleaseNoLongerShips(t *testing.T) {
	t.Run("own links of dropped artifacts are retracted", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		dropped := []string{toolSidecar, toolExtra, toolAlias, toolAliasChat}
		for _, name := range dropped {
			if got, want := readLink(t, filepath.Join(linkDir, name)), filepath.Join(env.versionDir(shrinkWideVersion), name); got != want {
				t.Fatalf("after %s, %s -> %q, want %q", shrinkWideVersion, name, got, want)
			}
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if got, want := readLink(t, filepath.Join(linkDir, toolName)), filepath.Join(env.versionDir(shrinkNarrowVersion), toolName); got != want {
			t.Errorf("%s -> %q, want %q", toolName, got, want)
		}
		for _, name := range dropped {
			if _, err := os.Lstat(filepath.Join(linkDir, name)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lstat(%s) error = %v, want not-exist: %s ships no %s", name, err, shrinkNarrowVersion, name)
			}
		}
	})

	t.Run("foreign entries are left alone", func(t *testing.T) {
		const userFile = "a user's own tk\n"
		otherTarget := filepath.Join("/opt", "other", toolAliasChat)
		elsewhereTarget := filepath.Join("/opt", "elsewhere", toolName+versionsSuffix, shrinkWideVersion, toolExtra)
		var renamedTarget string
		env := newShrinkEnv(t, func(env *fakeEnv, linkDir string) {
			if err := os.WriteFile(filepath.Join(linkDir, toolAlias), []byte(userFile), 0o755); err != nil {
				t.Fatalf("WriteFile(%s): %v", toolAlias, err)
			}
			if err := os.Symlink(otherTarget, filepath.Join(linkDir, toolAliasChat)); err != nil {
				t.Fatalf("Symlink(%s): %v", toolAliasChat, err)
			}
			// Into this manager's own tree, but at a name its links never carry.
			renamedTarget = filepath.Join(env.versionDir(shrinkWideVersion), toolName)
			if err := os.Symlink(renamedTarget, filepath.Join(linkDir, "toolkit-old")); err != nil {
				t.Fatalf("Symlink(toolkit-old): %v", err)
			}
			// This manager's shape at its own name, but under another root's versions directory.
			if err := os.Symlink(elsewhereTarget, filepath.Join(linkDir, toolExtra)); err != nil {
				t.Fatalf("Symlink(%s): %v", toolExtra, err)
			}
		})
		linkDir := filepath.Join(env.root, testLinkDir)

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		got, err := os.ReadFile(filepath.Join(linkDir, toolAlias))
		switch fi, lerr := os.Lstat(filepath.Join(linkDir, toolAlias)); {
		case lerr != nil:
			t.Errorf("the user's regular file %s is gone: %v", toolAlias, lerr)
		case !fi.Mode().IsRegular() || err != nil || string(got) != userFile:
			t.Errorf("the user's %s is now mode %v holding %q (%v), want the regular file %q", toolAlias, fi.Mode(), got, err, userFile)
		}
		for name, want := range map[string]string{
			toolAliasChat: otherTarget,
			"toolkit-old": renamedTarget,
			toolExtra:     elsewhereTarget,
		} {
			if got := readLink(t, filepath.Join(linkDir, name)); got != want {
				t.Errorf("foreign %s -> %q, want it untouched at %q", name, got, want)
			}
		}
		if _, err := os.Lstat(filepath.Join(linkDir, toolSidecar)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: a foreign neighbour must not stop the retraction", toolSidecar, err)
		}
	})

	t.Run("a crash-left staged link of a dropped artifact is retracted", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		staged := filepath.Join(linkDir, "."+toolExtra+".newlink")
		if err := os.Symlink(filepath.Join(env.versionDir(shrinkWideVersion), toolExtra), staged); err != nil {
			t.Fatalf("Symlink(%s): %v", staged, err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if _, err := os.Lstat(staged); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat(%s) error = %v, want not-exist: no later publish reuses that temp name", staged, err)
		}
	})

	t.Run("a tree without custody is not swept", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		if err := os.Chmod(env.versionsRoot(), 0o757); err != nil {
			t.Fatalf("Chmod(%s): %v", env.versionsRoot(), err)
		}

		if err := shrinkTo(t, env); !errors.Is(err, ErrNoCustody) {
			t.Fatalf("Ensure %s error = %v, want ErrNoCustody", shrinkNarrowVersion, err)
		}
		if got, want := readLink(t, filepath.Join(linkDir, toolSidecar)), filepath.Join(env.versionDir(shrinkWideVersion), toolSidecar); got != want {
			t.Errorf("%s -> %q, want it untouched at %q in a tree this manager may not mutate", toolSidecar, got, want)
		}
	})

	t.Run("a link dir resolving out of Root is not swept", func(t *testing.T) {
		env := newShrinkEnv(t, nil)
		linkDir := filepath.Join(env.root, testLinkDir)
		outside := filepath.Join(filepath.Dir(env.root), "outside")
		if err := os.Rename(linkDir, outside); err != nil {
			t.Fatalf("Rename(%s, %s): %v", linkDir, outside, err)
		}
		if err := os.Symlink(outside, linkDir); err != nil {
			t.Fatalf("Symlink the link dir out of Root: %v", err)
		}

		if err := shrinkTo(t, env); err != nil {
			t.Fatalf("Ensure %s: %v", shrinkNarrowVersion, err)
		}
		if got, want := readLink(t, filepath.Join(outside, toolSidecar)), filepath.Join(env.versionDir(shrinkWideVersion), toolSidecar); got != want {
			t.Errorf("%s outside Root -> %q, want it untouched at %q", toolSidecar, got, want)
		}
	})
}
