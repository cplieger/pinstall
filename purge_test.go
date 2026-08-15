package pinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The layout a previous installer of this package is imagined to have left behind.
// Every one of these facts is INJECTED: the library carries no knowledge of any
// consumer's migration history, which is why Purge is a parameter rather than
// behaviour.
const (
	legacyStagePrefix = ".toolkit-stage."
	legacyMarker      = ".toolkit-legacy-purged"
)

func legacyArtifacts() []string {
	return []string{
		".toolkit-update-in-progress",
		".toolkit-installed",
		".toolkit-ready",
		testLinkDir + "/.toolkit.prev",
		testLinkDir + "/.toolkit.prev.absent",
	}
}

func legacyNames() []string {
	return []string{toolName, toolSidecar, toolExtra}
}

// testPurge is the full injected sweep the tests drive.
func testPurge() *Purge {
	return &Purge{
		Artifacts:   legacyArtifacts(),
		Names:       legacyNames(),
		StagePrefix: legacyStagePrefix,
		Marker:      legacyMarker,
	}
}

// legacyFixture plants the whole previous layout, every entry in the SHAPE the old
// installer left it in (regular files, and a directory for the staging tree), which
// is what the sweep requires before it removes anything. It returns every path it
// created, relative to Root.
func legacyFixture(t *testing.T, root string) []string {
	t.Helper()
	for _, d := range []string{
		filepath.Join(root, testLinkDir),
		filepath.Join(root, legacyStagePrefix+"abc123"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", d, err)
		}
	}
	files := legacyArtifacts()
	for _, name := range legacyNames() {
		files = append(files, testLinkDir+"/"+name)
	}
	files = append(files, legacyStagePrefix+"abc123/leftover")
	for _, rel := range files {
		p := filepath.Join(root, rel)
		if err := os.WriteFile(p, []byte("legacy\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %v", p, err)
		}
	}
	return files
}

// TestPurgeDeletesTheWholeInjectedLayout pins the sweep: every declared artifact,
// every declared name under LinkDir, and every orphan staging tree goes -- and the
// co-owned link directory itself does not.
func TestPurgeDeletesTheWholeInjectedLayout(t *testing.T) {
	env := newFakeEnv(t)
	files := legacyFixture(t, env.root)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	m.purge()

	for _, rel := range files {
		if exists(filepath.Join(env.root, rel)) {
			t.Errorf("%s survived the purge", rel)
		}
	}
	if exists(filepath.Join(env.root, legacyStagePrefix+"abc123")) {
		t.Error("the orphan staging tree survived the purge")
	}
	if !exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("the purge removed the link directory, which another owner may co-own")
	}
	if !exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the completion marker was not recorded after a clean sweep")
	}
}

// TestPurgeRefusesAnEntryOfTheWrongShape pins the shape gate, which is what makes the
// sweep safe in a co-owned directory: another installer publishes a SYMLINK at
// exactly one of these names, and the old installer of this package never did, so a
// symlink there is somebody else's live pointer.
func TestPurgeRefusesAnEntryOfTheWrongShape(t *testing.T) {
	tests := map[string]struct {
		plant func(t *testing.T, root string) string
	}{
		"a symlink where a regular file is expected": {
			plant: func(t *testing.T, root string) string {
				other := filepath.Join(root, "other-owner-tree")
				if err := os.MkdirAll(other, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				link := filepath.Join(root, testLinkDir, toolName)
				if err := os.Symlink(other, link); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				return link
			},
		},
		"a directory where a regular file is expected": {
			plant: func(t *testing.T, root string) string {
				dir := filepath.Join(root, testLinkDir, toolSidecar)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				return dir
			},
		},
		"a regular file where a staging directory is expected": {
			plant: func(t *testing.T, root string) string {
				p := filepath.Join(root, legacyStagePrefix+"notadir")
				if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return p
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			if err := os.MkdirAll(filepath.Join(env.root, testLinkDir), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			spared := tc.plant(t, env.root)
			m := env.manager(func(c *Config) { c.Purge = testPurge() })

			m.purge()

			if !exists(spared) {
				t.Errorf("the sweep removed %s, whose shape the previous layout never had there", spared)
			}
		})
	}
}

// TestPurgeIsIdempotentAndSurvivesInterruption pins the two properties a start-time
// delete sequence needs. Every step is an independent RemoveAll of a fixed path, so a
// second run is a no-op and a run that starts from a half-swept volume finishes the
// job.
func TestPurgeIsIdempotentAndSurvivesInterruption(t *testing.T) {
	t.Run("idempotent", func(t *testing.T) {
		env := newFakeEnv(t)
		files := legacyFixture(t, env.root)
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purge()
		m.purge()
		m.purge()

		for _, rel := range files {
			if exists(filepath.Join(env.root, rel)) {
				t.Errorf("%s survived repeated purges", rel)
			}
		}
	})

	t.Run("no previous layout at all", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager(func(c *Config) { c.Purge = testPurge() })
		m.purge() // a swept volume: every step is a no-op
		if !exists(filepath.Join(env.root, legacyMarker)) {
			t.Error("a no-op sweep did not record completion")
		}
	})

	t.Run("resumes from a partially swept volume", func(t *testing.T) {
		env := newFakeEnv(t)
		files := legacyFixture(t, env.root)
		// Simulate a kill mid-sequence: a prefix of the deletes already ran.
		for _, rel := range []string{testLinkDir + "/" + toolName, ".toolkit-installed", ".toolkit-ready"} {
			if err := os.RemoveAll(filepath.Join(env.root, rel)); err != nil {
				t.Fatalf("RemoveAll(%s): %v", rel, err)
			}
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purge()

		for _, rel := range files {
			if exists(filepath.Join(env.root, rel)) {
				t.Errorf("%s survived the resumed purge", rel)
			}
		}
	})
}

// TestPurgeMarkerMakesTheSweepRunOncePerVolume pins the marker's two jobs: a recorded
// marker skips the sweep entirely, and a marker that is not a regular file is not
// evidence this manager wrote it, so the sweep runs again rather than trusting it.
func TestPurgeMarkerMakesTheSweepRunOncePerVolume(t *testing.T) {
	t.Run("a recorded marker skips the sweep", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		if err := os.WriteFile(filepath.Join(env.root, legacyMarker), []byte("done\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purgeOnce()

		if !exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep ran although the volume records it as complete")
		}
	})

	t.Run("a non-regular marker is not evidence", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		if err := os.MkdirAll(filepath.Join(env.root, legacyMarker), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		m := env.manager(func(c *Config) { c.Purge = testPurge() })

		m.purgeOnce()

		if exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep skipped on a marker it did not write")
		}
	})

	t.Run("an empty Marker sweeps on every start", func(t *testing.T) {
		env := newFakeEnv(t)
		legacyFixture(t, env.root)
		p := testPurge()
		p.Marker = ""
		m := env.manager(func(c *Config) { c.Purge = p })

		if m.purgeRecorded() {
			t.Error("purgeRecorded reported a marker although none is configured")
		}
		m.purge()
		if exists(filepath.Join(env.root, ".toolkit-installed")) {
			t.Error("the sweep did not run with no marker configured")
		}
		for _, e := range mustReadDir(t, env.root) {
			if strings.HasPrefix(e, ".toolkit-legacy") {
				t.Errorf("a marker %q was written although none is configured", e)
			}
		}
	})
}

// TestPurgeWithdrawsTheMarkerWhenSomethingCouldNotBeRemoved pins that the sweep never
// records a job it did not finish: an undeletable artifact leaves the marker unwritten
// so the next start retries.
//
// The only portable way to make a delete fail is to remove the permission to unlink,
// which root does not obey, so the case is skipped when the suite runs privileged. CI
// runs unprivileged, which is where this assertion earns its place.
func TestPurgeWithdrawsTheMarkerWhenSomethingCouldNotBeRemoved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only parent directory does not stop an unlink")
	}
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	// A non-empty directory whose own mode forbids unlinking its child.
	locked := filepath.Join(env.root, legacyStagePrefix+"locked")
	if err := os.MkdirAll(filepath.Join(locked, "child"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	m.purge()

	if exists(filepath.Join(env.root, legacyMarker)) {
		t.Error("the purge recorded completion although an artifact could not be removed")
	}
}

// TestPurgeRefusesTheRootItself pins the worst thing a mis-declared profile could ask
// for. "." passes the relative-path validation, so the shape gate is what stops the
// sweep from deleting the installation root: the root is not a regular file.
func TestPurgeRefusesTheRootItself(t *testing.T) {
	env := newFakeEnv(t)
	legacyFixture(t, env.root)
	m := env.manager(func(c *Config) {
		c.Purge = &Purge{Artifacts: []string{"."}, Marker: legacyMarker}
	})

	m.purge()

	if !exists(env.root) {
		t.Fatal("the sweep removed the installation root")
	}
	if !exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("the sweep removed the root's contents")
	}
}

// TestNilPurgeSweepsNothing pins the off switch: with no Purge configured the sweep
// does not run at all, and nothing a previous installer left is touched.
func TestNilPurgeSweepsNothing(t *testing.T) {
	env := newFakeEnv(t)
	files := legacyFixture(t, env.root)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, rel := range files {
		if rel == testLinkDir+"/"+toolName {
			// The convenience link republishes over this exact path.
			continue
		}
		if !exists(filepath.Join(env.root, rel)) {
			t.Errorf("%s was removed although no Purge is configured", rel)
		}
	}
	for _, e := range mustReadDir(t, env.root) {
		if strings.Contains(e, "legacy-purged") {
			t.Errorf("a purge marker %q was written although no Purge is configured", e)
		}
	}
}

// TestPurgeRunsOncePerProcess pins that the sweep is latched: it deletes the entry
// under LinkDir that is exactly where the convenience link is published, so a retry
// or a rescan must not delete it again.
func TestPurgeRunsOncePerProcess(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.Purge = testPurge() })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	link := filepath.Join(env.root, testLinkDir, toolName)
	if !exists(link) {
		t.Fatal("the convenience symlink was not published")
	}
	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if !exists(link) {
		t.Error("a second Ensure purged the convenience symlink it had just published")
	}
}

// TestConvenienceLinkPointsAtTheActiveArtifact pins the operator path: the link is
// republished as a symlink at the active version's artifact, so a bare-name lookup
// keeps resolving after the version-addressed move.
func TestConvenienceLinkPointsAtTheActiveArtifact(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	link := filepath.Join(env.root, testLinkDir, toolName)
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", link, err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink (mode %v)", link, fi.Mode())
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != m.Path() {
		t.Errorf("symlink target = %q, want the active artifact %q", target, m.Path())
	}
	// No temp link may be left behind by the atomic publish.
	if exists(filepath.Join(env.root, testLinkDir, "."+toolName+".newlink")) {
		t.Error("the staged temp link survived publication")
	}
}

// TestEmptyLinkDirPublishesNoLink pins the off switch by ABSENCE: with no LinkDir the
// directory is never created and the install is ready anyway, because the link was
// never an input to anything.
func TestEmptyLinkDirPublishesNoLink(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.LinkDir = "" })

	if err := m.Ensure(t.Context()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
	if exists(filepath.Join(env.root, testLinkDir)) {
		t.Error("a link directory was created although LinkDir is empty")
	}
	for _, e := range mustReadDir(t, env.root) {
		if e == toolName {
			t.Error("a bare artifact name was published under Root although LinkDir is empty")
		}
	}
}

// TestConvenienceLinkIsNeverConsultedForReadiness pins the other half: the link is
// CONVENIENCE ONLY. A failed publish, a dangling link, and a link replaced by a plain
// file must all leave readiness and Path untouched, because the manager never reads
// it.
func TestConvenienceLinkIsNeverConsultedForReadiness(t *testing.T) {
	t.Run("a failed publish does not withhold readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		link := filepath.Join(env.root, testLinkDir, toolName)
		env.onRename = failRenameTo(link)
		m := env.manager()

		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure error = %v, want nil: a convenience-link failure must not fail the install", err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true despite the link failure", why)
		}
		if exists(link) {
			t.Error("the link exists although its publish rename failed")
		}
	})

	t.Run("a sabotaged link does not affect a rescan", func(t *testing.T) {
		env := newFakeEnv(t)
		m := env.manager()
		if err := m.Ensure(t.Context()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		want := m.Path()
		link := filepath.Join(env.root, testLinkDir, toolName)
		if err := os.Remove(link); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		if err := os.Symlink(filepath.Join(env.root, "nowhere"), link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		ok, err := m.Rescan(t.Context())
		if !ok || err != nil {
			t.Fatalf("Rescan = (%v, %v), want (true, nil)", ok, err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true: the link is not an integrity input", why)
		}
		if got := m.Path(); got != want {
			t.Errorf("Path() = %q, want the version-directory path %q", got, want)
		}
	})
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
