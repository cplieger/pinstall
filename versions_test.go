package pinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestVersionDirCompleteRejectsEveryIncompleteShape pins what "complete" means. The
// sentinel is the ONLY thing that separates a finished install from a directory an
// interrupted one left behind, and it is checked against the directory's own name so
// a retained predecessor still reads as complete.
func TestVersionDirCompleteRejectsEveryIncompleteShape(t *testing.T) {
	tests := map[string]struct {
		setup func(t *testing.T, dir string)
		want  bool
	}{
		"complete set": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				writeSentinelFile(t, dir, pinnedVersion)
			},
			want: true,
		},
		"artifacts but no sentinel (interrupted install)": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
			},
		},
		"sentinel names another version": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				writeSentinelFile(t, dir, prevVersion)
			},
		},
		"missing required sidecar": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"missing primary artifact": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolSidecar)
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"required artifact is a symlink": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				target := filepath.Join(t.TempDir(), "elsewhere")
				if err := writeFakeBinary(target, pinnedVersion); err != nil {
					t.Fatalf("writeFakeBinary: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(dir, toolSidecar)); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"required artifact is not executable": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName)
				if err := os.WriteFile(filepath.Join(dir, toolSidecar), []byte("x"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				writeSentinelFile(t, dir, pinnedVersion)
			},
		},
		"sentinel is a symlink": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				other := filepath.Join(t.TempDir(), "sentinel")
				if err := os.WriteFile(other, []byte(pinnedVersion+"\n"), 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				if err := os.Symlink(other, filepath.Join(dir, sentinelName)); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
		},
		"sentinel is a directory": {
			setup: func(t *testing.T, dir string) {
				writeSet(t, dir, pinnedVersion, toolName, toolSidecar)
				if err := os.MkdirAll(filepath.Join(dir, sentinelName), 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m := env.manager()
			dir := env.versionDir(pinnedVersion)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			tc.setup(t, dir)
			if got := m.versionDirComplete(pinnedVersion); got != tc.want {
				t.Errorf("versionDirComplete = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSelectActiveIgnoresPartialDirectories pins that a partially written version
// directory is never a selection candidate: it is not complete, so selection skips
// it and falls back to the complete predecessor.
func TestSelectActiveIgnoresPartialDirectories(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(pinnedVersion)
	env.placeVersion(prevVersion)
	m := env.manager()

	sel, ok := m.selectActive(context.Background())
	if !ok {
		t.Fatal("selectActive found nothing, want the complete predecessor")
	}
	if sel.version != prevVersion {
		t.Errorf("selected %q, want %q -- a directory with no sentinel must not be selected", sel.version, prevVersion)
	}
}

// TestEnsurePrunesPartialsBeforeSelecting pins that Ensure removes a partial
// directory rather than leaving it to be re-probed forever, and that the staging
// trees of a previous crashed run go with it.
func TestEnsurePrunesPartialsBeforeSelecting(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(oldVersion)
	orphan := filepath.Join(env.versionsRoot(), stagePrefix+"crashed")
	if err := os.MkdirAll(filepath.Join(orphan, "home"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	m := env.manager()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if exists(env.versionDir(oldVersion)) {
		t.Error("the partial version directory survived Ensure")
	}
	if exists(orphan) {
		t.Error("the orphan staging tree survived Ensure")
	}
}

// TestSelectActiveExcludesAReplacedArtifactUnderAnIntactSentinel pins that a
// directory name plus a sentinel is not proof. The selected candidate is probed and
// must answer with the version its own directory claims, so an artifact replaced on
// the volume while the sentinel stayed intact is excluded -- falling back to another
// complete version and leaving the pin unsatisfied so the caller reinstalls.
func TestSelectActiveExcludesAReplacedArtifactUnderAnIntactSentinel(t *testing.T) {
	t.Run("excluded and the fallback serves when reinstall is impossible", func(t *testing.T) {
		env := newFakeEnv(t)
		tampered := env.placeVersion(pinnedVersion)
		env.placeVersion(prevVersion)
		// The sentinel still names the pin; only the artifact was swapped.
		if err := writeFakeBinary(filepath.Join(tampered, toolName), "6.6.6"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		env.installerFails = true
		m := env.manager()

		if err := m.Ensure(context.Background()); err == nil {
			t.Fatal("Ensure returned nil although the pin was replaced and reinstall failed")
		}
		if got := m.PathEntry(); got != env.versionDir(prevVersion) {
			t.Errorf("PathEntry() = %q, want the untampered predecessor %q", got, env.versionDir(prevVersion))
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true on the predecessor", why)
		}
	})

	t.Run("triggers a reinstall that replaces the tampered directory", func(t *testing.T) {
		env := newFakeEnv(t)
		tampered := env.placeVersion(pinnedVersion)
		if err := writeFakeBinary(filepath.Join(tampered, toolName), "6.6.6"); err != nil {
			t.Fatalf("writeFakeBinary: %v", err)
		}
		m := env.manager()

		if err := m.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if env.fetchCount() != 1 {
			t.Errorf("fetches = %d, want 1 -- a version-probe mismatch must trigger a reinstall", env.fetchCount())
		}
		out, err := env.probeAnswer(filepath.Join(tampered, toolName))
		if err != nil {
			t.Fatalf("probeAnswer: %v", err)
		}
		if got := LastFieldOfFirstLine(string(out)); got != pinnedVersion {
			t.Errorf("reinstalled artifact reports %q, want %q", got, pinnedVersion)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true after the reinstall", why)
		}
	})
}

// TestSelectActiveIgnoresExistingDirectoriesWithoutCustody pins the contract a
// tree without custody gets: a sentinel is a plain file and therefore trivially
// forgeable, unlike a digest, so a pre-existing version directory may not be
// activated -- only one this process installed from a verified archive.
//
// The trigger is the MEASURED verdict rather than the Untrusted flag. Untrusted
// waives the refusal to install into such a tree; it is not a declaration that the
// tree is bad, because a caller cannot be expected to know its volume carries an
// inherited ACL. So the fixture makes the root genuinely writable by others and
// then waives the install refusal, which is the real deployment this covers.
func TestSelectActiveIgnoresExistingDirectoriesWithoutCustody(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	if err := os.Chmod(env.root, 0o777); err != nil {
		t.Fatalf("chmod the install root: %v", err)
	}
	m := env.manager(func(c *Config) { c.InstallWithoutCustody = true })
	m.checkCustody()

	if _, ok := m.selectActive(context.Background()); ok {
		t.Fatal("selectActive accepted a pre-existing directory in a tree without custody")
	}
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if env.fetchCount() != 1 {
		t.Errorf("fetches = %d, want 1 -- a tree without custody must force a digest-verified reinstall", env.fetchCount())
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true after the verified reinstall", why)
	}
}

// TestRetainedAndPrunedVersions pins the retention invariant as a unit across every
// Retain value, including the axis no consumer exercises today (anything other than
// one). Retention is what makes a bad activation recoverable without a rollback
// journal, so it is asserted directly rather than only through Ensure.
func TestRetainedAndPrunedVersions(t *testing.T) {
	tests := map[string]struct {
		complete   []string
		active     string
		retain     int
		wantKeep   []string
		wantPruned []string
	}{
		"retain one: active plus predecessor": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"2.14.0", "2.13.9"},
		},
		"retain two keeps two predecessors": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     2,
			wantKeep:   []string{"2.14.2", "2.14.1", "2.14.0"},
			wantPruned: []string{"2.13.9"},
		},
		"retain three keeps every predecessor there is": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			active:     "2.14.2",
			retain:     3,
			wantKeep:   []string{"2.14.2", "2.14.1", "2.14.0", "2.13.9"},
			wantPruned: []string{},
		},
		"retain zero keeps only the active version": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0"},
			active:     "2.14.2",
			retain:     0,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{"2.14.1", "2.14.0"},
		},
		"a negative retain is treated as zero": {
			complete:   []string{"2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     -3,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{"2.14.1"},
		},
		"the predecessor is never pruned when the fallback is active": {
			complete:   []string{"2.14.1", "2.14.0"},
			active:     "2.14.1",
			retain:     1,
			wantKeep:   []string{"2.14.1", "2.14.0"},
			wantPruned: []string{},
		},
		"only the active version present": {
			complete:   []string{"2.14.2"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2"},
			wantPruned: []string{},
		},
		"a version newer than the active one is pruned (the pin moved down)": {
			complete:   []string{"2.15.0", "2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"2.15.0"},
		},
		"a newer version is pruned even at a high retain": {
			complete:   []string{"3.0.0", "2.15.0", "2.14.2", "2.14.1"},
			active:     "2.14.2",
			retain:     5,
			wantKeep:   []string{"2.14.2", "2.14.1"},
			wantPruned: []string{"3.0.0", "2.15.0"},
		},
		"numeric ordering, not lexical": {
			complete:   []string{"2.14.2", "2.9.9", "2.10.0"},
			active:     "2.14.2",
			retain:     1,
			wantKeep:   []string{"2.14.2", "2.10.0"},
			wantPruned: []string{"2.9.9"},
		},
		"nothing is pruned when no version is active": {
			complete:   []string{"2.14.2", "2.14.1", "2.14.0"},
			active:     "",
			retain:     1,
			wantKeep:   nil,
			wantPruned: nil,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// The two halves of retention, composed the way pruneSuperseded
			// composes them: the pure lexical candidate list, then the spare set,
			// then the victims. The usability half needs a filesystem and a
			// subprocess, so it is covered by the Ensure-level tests instead; here
			// every candidate is treated as usable, which is the healthy tree.
			var keep []string
			if tc.active != "" {
				candidates := predecessorCandidates(tc.complete, tc.active)
				retain := max(tc.retain, 0)
				keep = append([]string{tc.active}, candidates[:min(retain, len(candidates))]...)
			}
			got := slices.Sorted(slices.Values(keep))
			want := slices.Sorted(slices.Values(tc.wantKeep))
			if !slices.Equal(got, want) {
				t.Errorf("retained = %v, want %v", got, want)
			}
			var pruned []string
			if tc.active != "" {
				pruned = victimsOf(tc.complete, keep, nil)
			}
			prunedSorted := slices.Sorted(slices.Values(pruned))
			wantPruned := slices.Sorted(slices.Values(tc.wantPruned))
			if !slices.Equal(prunedSorted, wantPruned) {
				t.Errorf("victimsOf = %v, want %v", prunedSorted, wantPruned)
			}
			keep, pruned = got, prunedSorted
			for _, v := range pruned {
				if slices.Contains(keep, v) {
					t.Errorf("%q is both retained and pruned", v)
				}
			}
		})
	}
}

// TestEnsurePrunesToTheConfiguredRetention pins the invariant through Ensure, at the
// default retention and at a higher one: on a start that already has the pin, the
// retained predecessors survive and everything older is removed.
func TestEnsurePrunesToTheConfiguredRetention(t *testing.T) {
	tests := map[string]struct {
		retain int
		want   []string
	}{
		"default retention keeps one predecessor": {retain: 0, want: []string{pinnedVersion, prevVersion}},
		"retention of two keeps two":              {retain: 2, want: []string{pinnedVersion, prevVersion, oldVersion}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			for _, v := range []string{pinnedVersion, prevVersion, oldVersion, "2.13.0"} {
				env.placeVersion(v)
			}
			m := env.manager(func(c *Config) { c.Retain = tc.retain })

			if err := m.Ensure(context.Background()); err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			got := slices.Sorted(slices.Values(env.versionDirs()))
			want := slices.Sorted(slices.Values(tc.want))
			if !slices.Equal(got, want) {
				t.Errorf("version directories = %v, want %v", got, want)
			}
		})
	}
}

// TestEnsureFailedInstallPrunesNothing pins that a failed install never touches the
// fallback set. The versions on the volume are exactly what makes the failure
// survivable, so pruning runs only after a successful publish.
func TestEnsureFailedInstallPrunesNothing(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(prevVersion)
	env.placeVersion(oldVersion)
	env.installerFails = true
	m := env.manager()

	if err := m.Ensure(context.Background()); err == nil {
		t.Fatal("Ensure returned nil although the installer produced nothing")
	}
	got := slices.Sorted(slices.Values(env.versionDirs()))
	want := slices.Sorted(slices.Values([]string{oldVersion, prevVersion}))
	if !slices.Equal(got, want) {
		t.Errorf("version directories = %v, want %v -- a failed install must prune nothing", got, want)
	}
}

// TestLastFieldOfFirstLine pins the default probe parse: the last
// whitespace-separated field of the first line, so extra banner or trailing lines
// cannot change the answer.
func TestLastFieldOfFirstLine(t *testing.T) {
	tests := map[string]string{
		"toolkit 2.14.2\n":                     "2.14.2",
		"toolkit 2.14.2":                       "2.14.2",
		"toolkit 2.14.2\nextra 9.9.9\n":        "2.14.2",
		"  toolkit   2.14.2  \n":               "2.14.2",
		"2.14.2\n":                             "2.14.2",
		"":                                     "",
		"\n":                                   "",
		"   \n":                                "",
		"\ntoolkit 2.14.2\n":                   "",
		"toolkit version 2.14.2 (build abc)\n": "abc)",
	}
	for out, want := range tests {
		t.Run(strings.ReplaceAll(out, "\n", "\\n"), func(t *testing.T) {
			if got := LastFieldOfFirstLine(out); got != want {
				t.Errorf("LastFieldOfFirstLine(%q) = %q, want %q", out, got, want)
			}
		})
	}
}

// FuzzLastFieldOfFirstLine pins the default parser's invariants on arbitrary probe
// output: it never panics, the result is always a field of the FIRST line, and it
// never contains whitespace. A parsed version is compared against a directory name
// and a sentinel, so a parse that could return whitespace or a later line's content
// would be a real integrity problem.
func FuzzLastFieldOfFirstLine(f *testing.F) {
	for _, seed := range []string{
		"toolkit 2.14.2\n", "", "\n\n\n", "   ", "toolkit\t2.14.2\r\n",
		"a b c\nd e f\n", "2.14.2", "\x00 \x00", strings.Repeat("x ", 500),
		"../../etc/passwd", "v1 v2 ..", "\u00a0 1.0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, out string) {
		got := LastFieldOfFirstLine(out)
		if got == "" {
			return
		}
		if strings.ContainsAny(got, " \t\r\n\v\f") {
			t.Fatalf("LastFieldOfFirstLine(%q) = %q, which contains whitespace", out, got)
		}
		first, _, _ := strings.Cut(out, "\n")
		if !slices.Contains(strings.Fields(first), got) {
			t.Fatalf("LastFieldOfFirstLine(%q) = %q, which is not a field of the first line %q", out, got, first)
		}
	})
}

// TestCompareVersionsOrdersNumerically pins that version ordering is numeric per
// segment, because the retained-predecessor invariant is defined by "the newest
// version below the active one".
func TestCompareVersionsOrdersNumerically(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.14.2", "2.14.1", 1},
		{"2.14.1", "2.14.2", -1},
		{"2.14.2", "2.14.2", 0},
		{"2.10.0", "2.9.9", 1},
		{"2.14", "2.14.0", 0},
		{"2.14.1", "2.14", 1},
		{"2.14.2", "not-a-version", -1},
		{"10.0.0", "9.99.99", 1},
	}
	for _, tc := range tests {
		got := compareVersions(tc.a, tc.b)
		if (got > 0) != (tc.want > 0) || (got < 0) != (tc.want < 0) {
			t.Errorf("compareVersions(%q, %q) = %d, want sign of %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSortVersionsDescIsDeterministic pins that the newest-first ordering the
// selection and retention both read is total, including for entries that are not
// versions at all.
func TestSortVersionsDescIsDeterministic(t *testing.T) {
	in := []string{"2.9.9", "zzz", "2.14.2", "2.10.0", "2.14.2"}
	first := slices.Clone(in)
	sortVersionsDesc(first)
	second := slices.Clone(in)
	slices.Reverse(second)
	sortVersionsDesc(second)
	if !slices.Equal(first, second) {
		t.Errorf("sortVersionsDesc is input-order dependent: %v vs %v", first, second)
	}
	if first[0] != "zzz" && compareVersions(first[0], first[1]) < 0 {
		t.Errorf("sortVersionsDesc did not order newest first: %v", first)
	}
}

// TestSelectActiveExcludesAnUnparseableVersionAnswer pins that an artifact whose
// probe output carries no version is excluded rather than trusted. An empty parse
// must never be treated as "matches the directory name", because that would let a
// broken or replaced artifact activate.
func TestSelectActiveExcludesAnUnparseableVersionAnswer(t *testing.T) {
	tests := map[string]struct {
		out string
		err error
	}{
		"empty output":       {out: ""},
		"blank output":       {out: "   \n"},
		"probe failed":       {err: errors.New("timed out")},
		"leading blank line": {out: "\ntoolkit " + pinnedVersion + "\n"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			env.placeVersion(pinnedVersion)
			env.onProbe = func(string) ([]byte, error) { return []byte(tc.out), tc.err }
			m := env.manager()

			if sel, ok := m.selectActive(context.Background()); ok {
				t.Errorf("selectActive accepted %q (selected %q)", tc.out, sel.version)
			}
		})
	}
}

// TestSelfContainedRejectsEverythingButARegularExecutable pins the one predicate
// that decides whether an artifact survives the staging cleanup.
func TestSelfContainedRejectsEverythingButARegularExecutable(t *testing.T) {
	dir := t.TempDir()
	regularExec := filepath.Join(dir, "ok")
	if err := writeFakeBinary(regularExec, pinnedVersion); err != nil {
		t.Fatalf("writeFakeBinary: %v", err)
	}
	notExec := filepath.Join(dir, "plain")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regularExec, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	tests := map[string]struct {
		path string
		want bool
	}{
		"regular executable":           {path: regularExec, want: true},
		"regular but not executable":   {path: notExec},
		"symlink to a good executable": {path: link},
		"directory with the exec bit":  {path: subdir},
		"absent":                       {path: filepath.Join(dir, "nope")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := selfContained(tc.path); got != tc.want {
				t.Errorf("selfContained(%s) = %v, want %v", name, got, tc.want)
			}
		})
	}
}

// TestRemoveUnderRootCannotEscapeTheInstallationRoot pins the confinement on every
// delete this package performs: a symlinked entry under the root must not redirect a
// removal at whatever sits outside it.
func TestRemoveUnderRootCannotEscapeTheInstallationRoot(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()
	if err := os.MkdirAll(env.versionsRoot(), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	outside := filepath.Join(env.root, "precious")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	victim := filepath.Join(outside, "file")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(env.versionsRoot(), "escape")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	m.removeUnderRoot([]string{"escape"})

	if !exists(victim) {
		t.Error("a delete followed a symlink out of the installation root")
	}
}

func writeSet(t *testing.T, dir, version string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := writeFakeBinary(filepath.Join(dir, n), version); err != nil {
			t.Fatalf("writeFakeBinary(%s): %v", n, err)
		}
	}
}

func writeSentinelFile(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, sentinelName), []byte(version+"\n"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
}
