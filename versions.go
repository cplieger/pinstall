package pinstall

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// LastFieldOfFirstLine is the default [Release.ParseVersion]: the last
// whitespace-separated field of the first line, and "" when there is none. It
// covers the common `<name> <version>` and bare `<version>` shapes and never
// panics on arbitrary input.
//
// A release whose probe prints something else — JSON, a multi-column banner —
// sets its own parser, because probe output has no universal shape.
func LastFieldOfFirstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// selfContained reports whether path is an artifact that keeps working after the
// staging tree is removed: a REGULAR executable file, not a symlink. os.Stat
// follows links and a bare executable check is also true for a directory, so both
// are checked explicitly.
func selfContained(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// probeVersion asks an artifact for its version, bounded, and parses the answer
// with the release's parser.
func (m *Manager) probeVersion(ctx context.Context, bin string) (string, error) {
	out, err := m.run(ctx, &command{
		Path:    bin,
		Env:     binPathEnv(bin),
		Args:    m.cfg.Release.ProbeArgs,
		Timeout: probeTimeout,
	})
	if err != nil {
		return "", err
	}
	version := m.parseVersion(string(out))
	if version == "" {
		return "", fmt.Errorf("the version probe produced no parseable version at %s", bin)
	}
	return version, nil
}

// versionDirComplete reports whether a version directory is a completed install:
// the sentinel is a plain file naming exactly this version, and every required
// artifact inside is a self-contained executable.
//
// A directory populated file-by-file at its final name is indistinguishable from
// a finished install without the sentinel, so the sentinel is what separates an
// interrupted staging tree from a complete one — and it is checked against the
// directory's own name, not against the pin, so a retained predecessor still
// reads as complete.
func (m *Manager) versionDirComplete(version string) bool {
	dir := m.versionDir(version)
	sentinel := filepath.Join(dir, sentinelName)
	fi, err := os.Lstat(sentinel)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	// #nosec G304 -- sentinel is built from Root plus a directory entry name, and
	// it was just proved to be a regular file rather than a link.
	raw, err := os.ReadFile(sentinel)
	if err != nil || strings.TrimSpace(string(raw)) != version {
		return false
	}
	for _, name := range m.cfg.Require {
		if !selfContained(filepath.Join(dir, name)) {
			return false
		}
	}
	return true
}

// activatableVersions lists the complete version directories selection would
// consider, newest first: complete, and with no artifact another principal could
// rewrite. It is what retention counts.
func (m *Manager) activatableVersions() []string {
	complete := m.completeVersions()
	out := make([]string, 0, len(complete))
	for _, version := range complete {
		if m.wideArtifact(m.versionDir(version)) == "" {
			out = append(out, version)
		}
	}
	return out
}

// completeVersions lists the completed version directories, newest first.
func (m *Manager) completeVersions() []string {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		// Dot-prefixed entries are staging trees, never versions.
		if !e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !m.versionDirComplete(name) {
			continue
		}
		out = append(out, name)
	}
	sortVersionsDesc(out)
	return out
}

// trusted reports whether a version directory may be activated. A sentinel proves
// nothing on its own — it is a plain file, trivially forgeable, unlike a digest — so
// when the tree cannot be trusted only a version THIS process installed from a
// verified archive qualifies.
//
// TWO independent triggers, and both are needed:
//
//   - The measured custody verdict ([verifyCustody]). A caller cannot be expected to
//     know that its volume carries an inherited ACL, so the library finds out.
//   - [Config.Untrusted], unconditionally. It keeps the meaning it had before the
//     measurement existed, because measurement has blind spots a caller may know
//     about: a volume mounted into two containers whose processes both map to uid 0
//     passes every check here, and the flag is the only way to say so.
//
// What `installed` proves is worth stating exactly, because it is less than it looks:
// THIS process published that version from an archive whose digest matched, at some
// earlier point in its own life. It is not evidence that the bytes are unchanged
// since. In a tree without custody nothing can be, short of re-hashing every artifact
// on every start against a record kept in the same untrusted tree — which is why the
// README lists that as a deliberate non-goal rather than a missing feature. This is
// the strongest available claim in a situation the caller has been told about, not a
// guarantee equivalent to custody.
func (m *Manager) trusted(version string) bool {
	if m.cfg.Untrusted {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.installed[version]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.custodyErr == nil {
		return true
	}
	return m.installed[version]
}

// artifactPrivate reports whether path is a file that only this process's identity
// (or root) may write.
//
// Custody of the TREE does not answer this: directory write permission governs
// creating, removing and renaming entries, not writing to the contents of an entry
// that already exists. A group- or other-writable artifact inside a directory nobody
// else can add to is still a binary this package executes and another principal can
// rewrite.
//
// It asks the same three questions [verifyCustody] asks of a directory, for the same
// reasons: the mode's write bits, the owner (another user's file is that user's to
// chmod), and an ACL of a dialect whose mode is not an upper bound. Like everything
// else here it reads and reports; it never repairs.
func artifactPrivate(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if owner := int(stat.Uid); owner != os.Geteuid() && owner != 0 {
		return false
	}
	name, err := aclXattrPresent(path)
	return err == nil && name == ""
}

// wideArtifact returns the name of the first artifact in dir that another principal
// could rewrite, or "" when every one of them is private.
//
// Required AND optional, because both are executed. [Manager.PathEntry] hands the
// whole version directory to the front of PATH, and a multi-binary release's primary
// artifact resolves its sidecars from there by bare name, so an optional artifact is
// as much a root-executed binary as a required one. Only the artifacts this
// deployment declared are examined: anything else in the directory is not on the
// execution path.
//
// A missing optional artifact reads as private rather than wide — absence is the
// documented, warned-about case, not a rewritable binary.
func (m *Manager) wideArtifact(dir string) string {
	for _, name := range m.cfg.Require {
		if !artifactPrivate(filepath.Join(dir, name)) {
			return name
		}
	}
	for _, name := range m.cfg.Optional {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		if !artifactPrivate(path) {
			return name
		}
	}
	return ""
}

// selectActive picks the version to run: the pin when it is activatable, else the
// newest other complete version, else none.
//
// A directory name plus a sentinel is NOT proof. Before a candidate is accepted
// its primary artifact is probed and must answer with the version its own
// directory claims. A mismatch — an artifact replaced on the volume while the
// sentinel stayed intact — excludes that directory, falls through to another
// complete version if one exists, and leaves the pin unsatisfied so the caller
// reinstalls.
func (m *Manager) selectActive(ctx context.Context) (selection, bool) {
	for _, version := range preferPin(m.completeVersions(), m.cfg.Version) {
		if !m.trusted(version) {
			slog.Warn("ignoring an existing version directory because this process does not exclusively control the installation tree; only a freshly verified install may be activated",
				"package", m.cfg.Release.Name, "version", version, "reason", m.custodyVerdict(), "untrusted", m.cfg.Untrusted)
			continue
		}
		if verdict := m.custodyVerdict(); verdict != nil || m.cfg.Untrusted {
			slog.Error("activating a version on degraded evidence: this process installed it from a verified archive earlier, but the tree is not under its exclusive control, so nothing here proves the artifacts are unchanged since",
				"package", m.cfg.Release.Name, "version", version, "reason", verdict, "untrusted", m.cfg.Untrusted)
		}
		dir := m.versionDir(version)
		if wide := m.wideArtifact(dir); wide != "" {
			slog.Error("excluding a version directory: one of its artifacts is writable by another principal, so it is a binary this process would execute and somebody else could rewrite",
				"package", m.cfg.Release.Name, "version", version, "artifact", wide)
			continue
		}
		bin := filepath.Join(dir, m.primary)
		got, err := m.probeVersion(ctx, bin)
		if err != nil {
			slog.Warn("excluding a version directory: its artifact did not answer the version probe",
				"package", m.cfg.Release.Name, "version", version, "path", bin, "error", err)
			continue
		}
		if got != version {
			slog.Error("excluding a version directory: its artifact reports a different version than the directory and sentinel claim, so the install was replaced or tampered with",
				"package", m.cfg.Release.Name, "version", version, "reported", got,
				"path", bin, "error", ErrVersionMismatch)
			continue
		}
		return selection{version: version, dir: dir, bin: bin}, true
	}
	return selection{}, false
}

// preferPin returns versions with pin first (when present) and the rest in the
// given order, so the pinned version is always tried before any fallback.
func preferPin(versions []string, pin string) []string {
	out := make([]string, 0, len(versions))
	for _, v := range versions {
		if v == pin {
			out = append(out, v)
		}
	}
	for _, v := range versions {
		if v != pin {
			out = append(out, v)
		}
	}
	return out
}

// sortVersionsDesc orders versions newest first, comparing numeric segments
// numerically so 2.14.2 sorts above 2.9.0.
func sortVersionsDesc(versions []string) {
	slices.SortFunc(versions, func(a, b string) int { return compareVersions(b, a) })
}

// compareVersions returns >0 when a is newer than b, <0 when older, 0 when equal.
// Segments that are not numeric fall back to a string comparison, so an
// unexpected directory name still orders deterministically.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(as), len(bs)) {
		// A missing segment counts as zero, so 2.14 and 2.14.0 are the same
		// version rather than ordering by string.
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		an, aerr := strconv.Atoi(av)
		bn, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if an != bn {
				return an - bn
			}
			continue
		}
		if av != bv {
			return strings.Compare(av, bv)
		}
	}
	return 0
}

// retainedVersions names the version directories pruning must KEEP: the active
// version plus the `retain` newest complete versions below it, and nothing else.
// This is why no rollback journal is needed — a predecessor survives every
// switch, so a bad activation is recoverable by selecting it.
//
// Why per-version process leases are NOT taken: a retained set is only safe to
// prune from when no live process still holds a reference into a dropped
// directory. That holds when a new pin arrives only by restarting the consumer,
// which ends every process started against the old version. A consumer that
// enables LIVE in-place upgrades — a new pin reaching a running process without a
// restart — breaks that argument, because work started on version A could still
// reach into A's directory, and pruning would then have to take a per-version
// lease and remove a directory only at zero leases. Revisit this function first
// if that changes.
func retainedVersions(complete []string, active string, retain int) []string {
	if active == "" {
		return nil
	}
	older := make([]string, 0, len(complete))
	for _, v := range complete {
		if compareVersions(v, active) < 0 {
			older = append(older, v)
		}
	}
	sortVersionsDesc(older)
	if retain < 0 {
		retain = 0
	}
	return append([]string{active}, older[:min(retain, len(older))]...)
}

// versionsToPrune returns the complete version directories that are neither
// active nor among its retained predecessors. Anything NEWER than the active
// version is also pruned: reaching that state means the pin moved down, and a
// stale higher version is not a fallback the pin wants kept.
func versionsToPrune(complete []string, active string, retain int) []string {
	if active == "" {
		return nil
	}
	keep := retainedVersions(complete, active, retain)
	out := make([]string, 0, len(complete))
	for _, v := range complete {
		if !slices.Contains(keep, v) {
			out = append(out, v)
		}
	}
	return out
}

// pruneSuperseded removes every ACTIVATABLE version directory outside the retained
// set, then syncs the installation root again so the removals are durable. Failures
// warn: disk hygiene must not brick a start.
//
// Retention is computed over the activatable set rather than the complete one so a
// version excluded for holding a rewritable artifact cannot spend the retain slot
// that the usable predecessor needs — which would delete the fallback and leave the
// recovery guarantee resting on a directory selection already refuses. Such a version
// is also not a victim: it is left exactly as found, for the operator to look at.
func (m *Manager) pruneSuperseded(active string) {
	victims := versionsToPrune(m.activatableVersions(), active, m.cfg.Retain)
	if len(victims) == 0 {
		return
	}
	removed := m.removeUnderRoot(victims)
	if removed == 0 {
		return
	}
	slog.Info("pruned superseded versions",
		"package", m.cfg.Release.Name, "removed", removed, "active", active, "retain", m.cfg.Retain)
	if err := m.fsync(m.versionsDir); err != nil {
		slog.Warn("failed to sync the installation root after pruning",
			"package", m.cfg.Release.Name, "error", err)
	}
}

// prunePartials removes incomplete version directories and orphan staging trees.
// It runs before selection so a partial directory is never a candidate, and it
// runs while no staging tree of this manager exists — Ensure holds opMu and
// creates its stage later.
//
// Untrusted is deliberately NOT a delete trigger here: a foreign-writable root
// invalidates a directory for ACTIVATION (see trusted), and turning that flag
// into a mass delete would throw away the fallback set.
func (m *Manager) prunePartials() {
	entries, err := os.ReadDir(m.versionsDir)
	if err != nil {
		return
	}
	victims := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, stagePrefix):
			victims = append(victims, name)
		case !e.IsDir(), strings.HasPrefix(name, "."):
			continue
		case !m.versionDirComplete(name):
			victims = append(victims, name)
		}
	}
	if removed := m.removeUnderRoot(victims); removed > 0 {
		slog.Info("removed incomplete install directories",
			"package", m.cfg.Release.Name, "removed", removed)
	}
}

// removeUnderRoot deletes the named entries through an os.Root confined to the
// installation root, so a symlinked or otherwise redirected entry cannot make a
// delete escape the tree. It returns how many were removed.
func (m *Manager) removeUnderRoot(names []string) int {
	if len(names) == 0 {
		return 0
	}
	root, err := os.OpenRoot(m.versionsDir)
	if err != nil {
		slog.Warn("failed to open the installation root for pruning",
			"package", m.cfg.Release.Name, "error", err)
		return 0
	}
	defer root.Close()
	removed := 0
	for _, name := range names {
		if err := root.RemoveAll(name); err != nil {
			slog.Warn("failed to remove an install directory",
				"package", m.cfg.Release.Name, "entry", name, "error", err)
			continue
		}
		removed++
	}
	return removed
}
