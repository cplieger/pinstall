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

// usablePredecessors returns up to want complete versions older than active that could
// actually serve as a fallback, newest first.
//
// "Could serve" is the same question selection asks, and asking it here is what makes
// the retained predecessor a real fallback rather than a directory nothing will
// activate: private, and answering the version probe with the version its own directory
// claims. The README promises N predecessors as the recovery mechanism, so counting a
// directory that selection would refuse makes that promise false in exactly the
// situation it exists for.
//
// The walk stops as soon as it has want of them, so the cost is normally one bounded
// probe per prune — and pruning runs after a successful install, not on every start.
func (m *Manager) usablePredecessors(ctx context.Context, complete []string, active string, want int) []string {
	if want <= 0 {
		return nil
	}
	older := make([]string, 0, len(complete))
	for _, v := range complete {
		if compareVersions(v, active) < 0 {
			older = append(older, v)
		}
	}
	sortVersionsDesc(older)
	out := make([]string, 0, want)
	for _, version := range older {
		if len(out) == want {
			break
		}
		if m.usableAsFallback(ctx, version) {
			out = append(out, version)
		}
	}
	return out
}

// usableAsFallback reports whether a complete version directory would survive
// selection, and says why in the log when it would not.
func (m *Manager) usableAsFallback(ctx context.Context, version string) bool {
	dir := m.versionDir(version)
	if wide := m.wideArtifact(dir); wide != "" {
		slog.Warn("not counting a version directory towards retention: an entry in it is writable by another principal",
			"package", m.cfg.Release.Name, "version", version, "entry", wide)
		return false
	}
	got, err := m.probeVersion(ctx, filepath.Join(dir, m.primary))
	if err != nil || got != version {
		slog.Warn("not counting a version directory towards retention: it would not survive selection's version probe",
			"package", m.cfg.Release.Name, "version", version, "reported", got, "error", err)
		return false
	}
	return true
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
// without custody of the tree the answer is no: not for any directory found there, and
// not even for one this process installed, unless the caller has explicitly waived the
// precondition and accepted that weaker claim.
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
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.cfg.Untrusted:
		// The waiver's degraded mode: the caller accepted a tree it shares, and the
		// mitigation on offer is that only what this process published from a verified
		// archive is activated.
		return m.installed[version]
	case m.custodyErr != nil:
		// No custody and no waiver. Nothing here is evidence, INCLUDING what this
		// process installed earlier: that fact proves a publish at some past instant,
		// not the bytes at this one, and in a writable tree the directory or the
		// artifact can be renamed between the checks and the exec. Readiness is
		// withheld rather than granted on a claim the library cannot make.
		return false
	}
	return true
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

// dirPrivate reports whether a version directory is one only this process's identity
// (or root) may add to, remove from or rename within.
//
// The custody walk stops at the installation root, so this is the check for one level
// below it. It matters because a version directory is not always one this process
// created: an operator is encouraged to reshape the volume, and a tree restored from a
// backup can hold a directory with another owner or a wider mode. Without it, a
// foreign-owned version directory passes on the strength of its artifacts' modes while
// its owner can replace those entries between the check and the exec.
func dirPrivate(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsDir() {
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

// wideArtifact returns the name of the first entry in dir that another principal could
// rewrite, or "" when the directory and everything in it is private. The directory
// itself answers as "." — one another principal can write makes the modes of the
// entries inside it irrelevant, since the entries can simply be replaced.
//
// EVERY top-level entry, not only the declared artifacts. [Manager.PathEntry] hands the
// whole version directory to the front of PATH, and a multi-binary release's primary
// artifact resolves its sidecars from there by bare name, so an undeclared executable
// sitting in that directory is reachable too. A version directory is not always one
// this process created: an operator is encouraged to reshape the volume, and a tree
// restored from a backup can hold entries with another owner. Directory permissions
// govern adding, removing and renaming names; they do not stop the owner of an entry
// that is already there from rewriting it, which is why dirPrivate alone is not enough.
//
// Top level only, because that is what PATH exposes: an executable in a subdirectory
// is not reachable by bare name. A directory this library assembled holds exactly the
// declared artifacts and the sentinel, so this is a handful of stats.
func (m *Manager) wideArtifact(dir string) string {
	if !dirPrivate(dir) {
		return "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "."
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !artifactPrivate(filepath.Join(dir, e.Name())) {
			return e.Name()
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
		if m.cfg.Untrusted {
			slog.Error("activating a version on degraded evidence: Config.Untrusted waives custody of the tree, so all that is known is that this process published this version from a verified archive earlier, not that its artifacts are unchanged since",
				"package", m.cfg.Release.Name, "version", version, "reason", m.custodyVerdict())
		}
		dir := m.versionDir(version)
		if wide := m.wideArtifact(dir); wide != "" {
			if wide == "." {
				slog.Error("excluding a version directory: the directory itself is writable by another principal, who can therefore replace any artifact in it whatever the artifacts' own modes say",
					"package", m.cfg.Release.Name, "version", version, "dir", dir)
			} else {
				slog.Error("excluding a version directory: an entry in it is writable by another principal, so it is a file this process may execute and somebody else could rewrite",
					"package", m.cfg.Release.Name, "version", version, "entry", wide)
			}
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

// pruneSuperseded removes the version directories outside the retained set, then syncs
// the installation root again so the removals are durable. Failures warn: disk hygiene
// must not brick a start.
//
// The retained set is the active version plus up to Retain predecessors that could
// ACTUALLY serve (see usablePredecessors). A directory that selection would refuse —
// one holding a rewritable entry, or whose binary disagrees with its own name — must
// not spend the slot the usable predecessor needs, because that deletes the fallback
// and leaves the recovery guarantee resting on something nothing will activate.
//
// Such a directory is also never a victim. It is left exactly as found, for the
// operator to look at: this library did not put it in that state and deleting evidence
// is not its call.
func (m *Manager) pruneSuperseded(ctx context.Context, active string) {
	complete := m.completeVersions()
	keep := append([]string{active}, m.usablePredecessors(ctx, complete, active, m.cfg.Retain)...)
	victims := make([]string, 0, len(complete))
	for _, version := range complete {
		if slices.Contains(keep, version) {
			continue
		}
		if !m.usableAsFallback(ctx, version) {
			continue
		}
		victims = append(victims, version)
	}
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
// Untrusted does not change WHAT is swept, only whether sweeping happens at all: its
// caller runs this and the purge only when Manager.mayMutateTree allows, and the flag
// is one of the two ways that returns true. A foreign-writable tree invalidates a
// directory for ACTIVATION (see trusted); it has never been a reason to delete more
// than the incomplete directories this sweep already targets, because that would throw
// away the fallback set.
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
