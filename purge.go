//go:build linux

package pinstall

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// purgeTarget is one entry the sweep may remove: its path relative to Root, and
// the file SHAPE the previous installer left there.
//
// The shape is a gate, not decoration. The directory a convenience link lives in
// is commonly co-owned — another installer may publish a SYMLINK at exactly one
// of these names — while an old installer of this package only ever moved real
// files there and only ever created its staging trees as directories. So "regular
// file" and "directory" are exactly what this sweep is entitled to delete, and
// anything else at the same path belongs to someone else.
type purgeTarget struct {
	// path is relative to Root.
	path string
	// dir marks a target the previous installer created as a directory; every
	// other target must be a regular file.
	dir bool
}

// validate rejects a purge whose paths could escape Root. Every target is deleted
// through an os.Root confined to Root, but refusing a traversal at construction
// reports the profile's mistake instead of silently sweeping nothing.
func (p *Purge) validate(linkDir string) error {
	for i, path := range p.Artifacts {
		if err := validateRelPath(fmt.Sprintf("Purge.Artifacts[%d]", i), path, false); err != nil {
			return err
		}
	}
	for i, name := range p.Names {
		if err := validateComponent(fmt.Sprintf("Purge.Names[%d]", i), name); err != nil {
			return err
		}
	}
	if len(p.Names) > 0 && linkDir == "" {
		return fmt.Errorf("pinstall: Purge.Names sweeps entries under LinkDir, which is empty (name %q has no directory to be swept from)", p.Names[0])
	}
	if p.StagePrefix != "" && !strings.HasPrefix(p.StagePrefix, ".") {
		return fmt.Errorf("pinstall: Purge.StagePrefix %q must start with a dot, so a version scan cannot reach what it matches", p.StagePrefix)
	}
	if p.Marker != "" {
		switch {
		case !strings.HasPrefix(p.Marker, "."):
			return fmt.Errorf("pinstall: Purge.Marker %q must start with a dot, so no version scan can mistake it for a version", p.Marker)
		case strings.ContainsRune(p.Marker, '/'), strings.ContainsRune(p.Marker, filepath.Separator):
			return fmt.Errorf("pinstall: Purge.Marker %q must be a single path component directly under Root", p.Marker)
		case p.Marker == "." || p.Marker == "..":
			return fmt.Errorf("pinstall: Purge.Marker must not be %q", p.Marker)
		}
	}
	return nil
}

// purgeOnce runs the sweep at most once per process AND at most once per volume.
// The in-process latch protects the convenience link this manager publishes at one
// of the swept paths; the on-disk marker is what stops a start that has nothing
// left to migrate from walking a co-owned directory at all.
func (m *Manager) purgeOnce() {
	if m.cfg.Purge == nil {
		return
	}
	m.mu.Lock()
	already := m.purged
	m.purged = true
	m.mu.Unlock()
	if already {
		return
	}
	if m.purgeRecorded() {
		slog.Debug("skipping the one-shot purge: it is already recorded as complete on this volume",
			"package", m.cfg.Release.Name, "marker", m.cfg.Purge.Marker)
		return
	}
	m.purge()
}

// purge deletes the previous installer's layout — the named artifacts, the named
// entries under LinkDir, and every orphan staging tree — and NOTHING else. Each
// target is removed only when what is on disk has the shape the previous installer
// left there; a mismatch is another owner's file and is refused.
//
// It is idempotent and interruption-safe by construction: each step is an
// independent RemoveAll of a path nothing reads afterwards, so a kill leaves a
// prefix done and the next start repeats the sequence, and on an already-swept
// volume every step is a no-op. Failures warn and continue — an undeleted artifact
// is inert, and bricking a start over disk hygiene is worse — but they also
// withhold the completion marker, so the next start retries instead of recording a
// job it did not finish.
func (m *Manager) purge() {
	root, err := os.OpenRoot(m.cfg.Root)
	if err != nil {
		// A missing root means there is nothing to purge; anything else is worth
		// a line.
		if !os.IsNotExist(err) {
			slog.Warn("failed to open the root to purge a previous installer's layout",
				"package", m.cfg.Release.Name, "error", err)
		}
		return
	}
	defer root.Close()

	removed, failed := 0, 0
	for _, t := range m.purgeTargets(root) {
		present, matches := purgeShapeMatches(root, t)
		switch {
		case !present:
			continue
		case !matches:
			slog.Warn("refusing to remove an entry the previous layout never had this shape at; it belongs to another owner of this tree and that owner's state still claims it",
				"package", m.cfg.Release.Name, "entry", t.path, "want_shape", shapeName(t.dir))
		default:
			// RemoveAll through the root confines the delete to this tree: a
			// symlinked artifact cannot redirect it at whatever sits next door.
			if err := root.RemoveAll(t.path); err != nil {
				failed++
				slog.Warn("failed to remove an artifact of the previous layout; it is inert, so the start continues",
					"package", m.cfg.Release.Name, "entry", t.path, "error", err)
				continue
			}
			removed++
		}
	}
	if removed == 0 {
		slog.Debug("no previous layout to purge", "package", m.cfg.Release.Name)
	} else {
		slog.Info("purged a previous installer's layout; the pinned version is installed fresh into its own version directory",
			"package", m.cfg.Release.Name, "removed", removed)
	}
	if failed > 0 {
		slog.Warn("not recording the purge as complete: some artifacts could not be removed, so the next start retries the sweep",
			"package", m.cfg.Release.Name, "failed", failed)
		return
	}
	m.recordPurge()
}

// purgeTargets assembles the sweep's fixed target list. There is no scan of the
// co-owned link directory: only the names the profile declared are considered, so
// nothing another owner put there is ever a candidate.
func (m *Manager) purgeTargets(root *os.Root) []purgeTarget {
	p := m.cfg.Purge
	out := make([]purgeTarget, 0, len(p.Artifacts)+len(p.Names)+4)
	for _, path := range p.Artifacts {
		out = append(out, purgeTarget{path: path})
	}
	for _, name := range p.Names {
		out = append(out, purgeTarget{path: filepath.Join(m.cfg.LinkDir, name)})
	}
	return append(out, orphanStages(root, p.StagePrefix)...)
}

// purgeShapeMatches reports whether anything is at t.path, and whether it has the
// shape the previous installer left there. Lstat, never Stat: a symlink at a swept
// path is precisely the foreign artifact this gate exists to spare, so it must not
// be resolved to whatever it points at.
func purgeShapeMatches(root *os.Root, t purgeTarget) (present, matches bool) {
	fi, err := root.Lstat(t.path)
	if err != nil {
		return false, false
	}
	if t.dir {
		return true, fi.IsDir()
	}
	return true, fi.Mode().IsRegular()
}

// shapeName names a target's expected shape for the refusal log line.
func shapeName(dir bool) string {
	if dir {
		return "directory"
	}
	return "regular file"
}

// orphanStages lists orphan staging trees directly under Root. The prefix is
// dot-leading, so it cannot match the installation root that now sits in the same
// directory, and an empty prefix matches nothing rather than everything.
func orphanStages(root *os.Root, prefix string) []purgeTarget {
	if prefix == "" {
		return nil
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil
	}
	out := make([]purgeTarget, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, purgeTarget{path: e.Name(), dir: true})
		}
	}
	return out
}

// purgeRecorded reports whether the completion marker is on the volume. A
// non-regular file at that path is NOT a marker: the sweep would rather run again
// (it is idempotent) than skip on evidence it did not write. An empty Marker means
// the profile asked for the sweep on every start.
func (m *Manager) purgeRecorded() bool {
	if m.cfg.Purge.Marker == "" {
		return false
	}
	fi, err := os.Lstat(filepath.Join(m.cfg.Root, m.cfg.Purge.Marker))
	return err == nil && fi.Mode().IsRegular()
}

// recordPurge writes the completion marker durably. A failure only warns: the
// only consequence is that the next start repeats a sweep which is by then a
// no-op on every path it looks at.
func (m *Manager) recordPurge() {
	if m.cfg.Purge.Marker == "" {
		return
	}
	path := filepath.Join(m.cfg.Root, m.cfg.Purge.Marker)
	stamp := m.now().UTC().Format("2006-01-02T15:04:05Z") + "\n"
	if err := m.writeFileDurably(path, []byte(stamp), fileMode); err != nil {
		slog.Warn("failed to record that the purge completed; the sweep repeats on the next start, which is a no-op on a swept volume",
			"package", m.cfg.Release.Name, "path", path, "error", err)
		return
	}
	slog.Debug("recorded the purge as complete", "package", m.cfg.Release.Name, "path", path)
}

// publishConvenienceLink republishes <Root>/<LinkDir>/<Binary> as a symlink at
// the active artifact, for an operator shelling into the environment. An empty
// LinkDir publishes nothing.
//
// It is explicitly NON-AUTHORITATIVE: nothing in this package reads it, no
// integrity or readiness decision consults it, and a consumer always runs the
// absolute version-directory path from [Manager.Path]. Publication is atomic
// (write a temp name, rename over the old one) with the parent synced and the
// target validated, and every failure is a warning — a missing convenience
// pointer must never withhold readiness from a correctly installed release.
func (m *Manager) publishConvenienceLink(target string) {
	if m.cfg.LinkDir == "" {
		return
	}
	if !selfContained(target) {
		slog.Warn("not publishing the convenience symlink: the active artifact is not a self-contained executable",
			"package", m.cfg.Release.Name, "target", target)
		return
	}
	linkDir := filepath.Join(m.cfg.Root, m.cfg.LinkDir)
	if err := os.MkdirAll(linkDir, dirMode); err != nil {
		slog.Warn("failed to create the link dir for the convenience symlink",
			"package", m.cfg.Release.Name, "path", linkDir, "error", err)
		return
	}
	link := filepath.Join(linkDir, m.primary)
	tmp := filepath.Join(linkDir, "."+m.primary+".newlink")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		slog.Warn("failed to stage the convenience symlink",
			"package", m.cfg.Release.Name, "path", tmp, "error", err)
		return
	}
	if err := m.rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		slog.Warn("failed to publish the convenience symlink; the bare name will not resolve, the primary path is unaffected",
			"package", m.cfg.Release.Name, "path", link, "error", err)
		return
	}
	if err := m.fsync(linkDir); err != nil {
		slog.Warn("failed to sync the link dir after publishing the convenience symlink",
			"package", m.cfg.Release.Name, "error", err)
	}
	slog.Debug("published the convenience symlink",
		"package", m.cfg.Release.Name, "path", link, "target", target)
}
