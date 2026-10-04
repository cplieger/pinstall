# Non-goals

These are deliberate omissions, not missing features. Each section says what pinstall leaves out and why, for a developer deciding whether it fits.

## Signature or attestation checks

The trust anchor is the digest you pinned, which you got out of band. Check a signature where you produce the pin, not where you consume it.

## Per-file digests checked again at activation

This would catch silent corruption. The digest would be one pinstall computed itself and stored in the same tree as the artifact, though. The only attacker the custody check leaves is one who can write there, and to that attacker the record is as easy to forge as the binary. It would sound stronger without being stronger.

Making it mandatory would also delete every existing version directory on upgrade. Making it optional would make it a check that skips itself when its input is missing.

## Repairing permissions it finds wrong

Custody is checked and refused, never fixed. Changing the mode of someone else's directory is an authority pinstall does not have. Forcing an exact mode would widen a tree a stricter umask had narrowed. The operator who set the permission would never learn that pinstall disagreed.

## Resolving "latest"

A resolved version is not a pin. Whatever bumps your version and digest literals owns that decision, and pinstall installs exactly what it is told.

## Rollback, journals and backups

Nothing is overwritten in place, so there is no half-promoted state to recover from. The retained predecessor is the recovery.

## Archive formats other than zip

One unpacker, `UnpackZip`, ships with tests. A `tar.gz` release needs your own `Unpacker` function, which reads the verified archive from the `*io.SectionReader` and writes through the `os.Root` it receives. A format setting with one working value would be a partly built public API.

## Windows and macOS

The publish protocol relies on a rename within one filesystem and on syncing a directory. The confined deletes use `os.Root`, and the custody check reads Unix ownership and Linux extended attributes. pinstall builds on Linux only.

## Changing the version inside a running process

Retention assumes a new pin arrives by restarting your program. Changing versions live would need a per-version lease before a directory could be pruned.
