# How pinstall works

This page describes what pinstall does on disk and why, for a developer who wants to know the guarantees before relying on them. The field reference is [Configuration](configuration.md).

## The install layout

Each version installs into its own directory under `Root`:

```text
<Root>/
├── <Name>-versions/
│   ├── 1.4.2/            # the active version: artifacts + .complete
│   └── 1.4.1/            # the retained predecessor
├── <Name>-state.json     # a diagnostic record; never an input to Ready
└── bin/<Binary>          # the optional convenience symlink
```

Your program finds the active version through `Path()` and `PathEntry()`, never through the symlink. The symlink exists only so an operator can run the tool by name, and pinstall never reads it. The state file is for an operator reading the volume, and `Ready` never consults it.

## A version is complete or absent

Artifacts are written into a staging tree, and each one is synced. A `.complete` marker naming the version is written and synced last. The staging directory is synced, renamed into place, and its parent is synced.

An interrupted install has no marker, so it is never a candidate for activation. Nothing is overwritten in place, so there is no half-promoted state to recover from and no rollback journal. Any sync failure, a full disk included, fails the install and keeps the complete versions already on disk.

## Custody of the install root

Every guarantee rests on one claim. The artifact pinstall activates came out of an archive that matched your pinned digest. The digest is checked once, on the bytes as they arrive. After that, the claim holds only while nobody else can write into the tree.

So pinstall checks custody before it fetches anything. The root and every directory above it must be owned by you or root and writable by nobody else. This holds on the path as written, on the path it resolves to, and on the directory that holds each symlink in between. A chain of more than 40 symlinks is refused.

The version directory and every entry in it get the same questions at publish and again at activation. A file's mode is independent of its directory's. A symlink inside a version directory is refused.

pinstall refuses rather than fixing what it finds. `ErrNoCustody` names the path it refused. Changing the mode of someone else's directory is an authority pinstall does not have. Forcing an exact mode would also widen a tree a stricter umask had narrowed.

### Access-control lists

A directory reading `0755 root:root` can still carry an access-control list that gives a named user full write. So when a path carries one, pinstall parses it. It reads POSIX.1e lists (`system.posix_acl_access`) and NFSv4 lists as OpenZFS serves them (`system.nfs4_acl_xdr`), and judges the identities they grant write to. A refusal then names a principal, such as uid 3000, rather than declining to look.

A list that cannot be read is a refusal, never an absence. That covers a malformed list, an unrecognised field, a value longer than any list it accepts, and a `getxattr` call a sandbox denies. The NFS client's own `system.nfs4_acl` carries user names rather than numeric IDs, so it is refused with `ErrACLDialectUnsupported`. That error wraps `ErrACLUnreadable`.

### Two exemptions

A sticky ancestor that others can write to passes, because the sticky bit stops another user renaming your directory away. That is what makes `/tmp` usable as a root. The exemption is lost when an access-control list grants someone `DELETE_CHILD`, ownership of that directory, or the right to rewrite its list. Write access is read from the list as well as the mode, so a `1755` directory with an `EVERYONE@` write entry counts as shared.

Group 0 counts as trusted, so the check does not guard against an account that belongs to group 0.

### When custody fails

`TrustedUIDs` and `TrustedGIDs` declare an identity that is already privileged, and keep the check enforcing for everyone else. [Trusted identities](configuration.md#trusted-identities) shows how to set them. `InstallWithoutCustody` installs anyway, for a filesystem that does not make the mode its access decision at all. It costs a digest-verified reinstall on every start, because a completion marker in a tree others can write is not evidence. `Untrusted` only restricts activation to versions this process installed.

Without custody and without the waiver, nothing is activated, and the error is `ErrNoCustody` rather than `ErrNoVersion`.

## The verified archive has no name

The archive is created inside the install root and unlinked before its first byte arrives. The same open file carries those bytes through the digest check and into the extraction. Nothing can be pointed at another file in between, no temporary directory's permissions matter, and nothing is left behind if the process dies mid-download.

The unpacker receives a reader over that file and an `os.Root` on the destination. The kernel then refuses an archive entry that names its way out. A custom `Unpacker` is ordinary Go code and can still go around the root, so writing it correctly stays your job.

## Every activation is checked

The `.complete` marker is a plain file, so it records a finished install but proves nothing on its own. Custody is what protects the tree. Before a version is activated, pinstall also runs its primary artifact with `ProbeArgs`, and the artifact must answer with the version its directory claims.

An artifact replaced under an intact marker is excluded. pinstall falls back to another complete version, and the pin stays unsatisfied so the next pass reinstalls it.

## Assertions

An `Assertion` is a bounded command run against the installed artifact, given as the full argument list after the artifact's path. pinstall needs to know nothing about how the package is configured.

A required assertion runs twice. It runs against the staged artifact before publication, so a candidate that fails it never becomes a version directory. It runs again against the active artifact on every pass, because its effect usually lives in the package's own configuration and can change. A required failure withholds readiness, and any other failure only warns.

`Release.Mandatory` is the set a deployment cannot weaken, reword or drop. Whatever a caller passes, each mandatory assertion is forced to required and uses the profile's own arguments. `New` refuses a profile that declares none.

The most common mandatory assertion turns off self-update, because a binary that replaces itself invalidates the digest you checked. "This package needs no post-install check" looks the same as "the profile author forgot". A package that genuinely needs no gate declares its cheapest positive check instead, so the choice is written down on purpose.

## Failures and retries

A failed install leaves every complete version on the volume serving. Pruning runs only after a successful publish, because those directories are the fallback set.

`EnsureWithRetry` retries with a backoff that doubles from `RetryBackoff` up to 10 minutes, for at most `MaxAttempts` attempts. It never exits your process. `Rescan` picks up a repair made in place, such as a restored version directory, without downloading or restarting.

A `Manager` is safe for concurrent use. `Ensure` and `Rescan` run one at a time, and the readers never wait behind an install.

## Writes stay under Root

pinstall uses an `os.Root` whenever it acts on a name that comes from a profile, an archive or a tree already on disk. That covers archive entries, the artifacts moved out of the staging tree, the version directory a publish replaces, the state record, the sweep marker, the convenience link and every sweep target. The kernel then refuses a symlink at any path component instead of following it.

The staging tree, the archive file and the completion marker have names pinstall generates itself. It creates them inside the versions directory, whose custody it checked first.

The custody check covers the versions directory and the directories above it. Three places it does not cover rely on `os.Root` confinement instead:

- the `LinkDir` directory, which other installers often share
- `Root` itself, which holds the state record and the sweep marker
- the staging tree an in-archive installer fills

## Downloads

pinstall fetches the archive with its own HTTP client and accepts only a `200 OK` response. The TLS handshake and the response headers each have 20 seconds. The body has no total deadline, but a transfer that makes no progress for 60 seconds is cancelled. The body is capped at 2 GiB. An empty body is refused as a partial download rather than reported as a digest mismatch.

The client does not read proxy settings from the environment. Use `Config.URLTemplate` to point at a mirror your program can reach.

Version probes and assertions each have 10 seconds. An in-archive installer has 2 minutes unless its `Timeout` says otherwise, and its exit code alone does not fail the install. What decides is whether the artifacts it produced pass the staged checks.

## Sweeping an earlier installer's layout

If an earlier installer put the same package on this volume in a different layout, `Config.Purge` removes what it left behind. It runs once per volume, recorded by a marker file. It is passed in rather than built in, because the leftovers are a fact about one deployment's history, not about the package.

Each target is removed only when what is on disk has the shape the old installer left there. A declared artifact must be a regular file, and a staging tree must be a directory. Another installer may publish symlinks in the shared `LinkDir` directory. So a symlink at a swept path belongs to someone else, and it is refused rather than deleted. Deletes go through `os.Root`, so a redirected entry cannot reach outside `Root`.

A target that could not be removed withholds the marker, so the next pass retries the sweep. `kirocli.ShellEraDispatchers()` lists the names an older kiro-cli shell installer left in a shared bin directory.

## Logging

pinstall logs through the default `log/slog` logger. It logs install attempts, retries, the release's `Notice`, and warnings about versions it skips or does not count towards retention. `ParseIdentities` logs nothing.
