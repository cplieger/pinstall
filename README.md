# pinstall

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/pinstall/v2.svg)](https://pkg.go.dev/github.com/cplieger/pinstall/v2)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/pinstall)](https://github.com/cplieger/pinstall/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/pinstall/badges/coverage.json)](https://github.com/cplieger/pinstall/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/pinstall/badges/mutation.json)](https://github.com/cplieger/pinstall/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13867/badge)](https://www.bestpractices.dev/projects/13867)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/pinstall/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/pinstall)

> Digest-pinned installs of an upstream release: version-addressed, revalidated, with a verdict

A Go library for programs that must install a specific version of some other program and then depend on it. You give it a URL template, the version you pinned, and the SHA-256 of each architecture's archive. It downloads the archive, refuses anything whose digest does not match, installs it into a version-addressed directory, re-probes the binary it is about to activate, re-asserts the settings your install depends on, keeps N predecessors as a fallback, and reports whether the result is usable.

It is the piece you would otherwise write in a shell script, with the failure modes that script usually has: a half-written install directory that looks finished, a binary that silently self-updated out from under the digest you verified, a partial download reported as a checksum mismatch, and no way to tell "still installing" from "gave up".

Nothing here exits your process, reads the environment, or does work at import time. One dependency outside the standard library, `cplieger/pathinside`, which is itself standard-library-only. Linux only.

## Why it is shaped this way

Six decisions drive everything else:

- **A version directory is complete or it does not exist.** Artifacts are written into a staging tree, each one is synced, a `.complete` sentinel naming the version is written and synced _last_, the directory is synced, and only then is it renamed into place. An interrupted install is detectable by the absence of the sentinel and is never a selection candidate. Atomic visibility is not crash durability, which is why the syncs are separate steps rather than an afterthought.
- **Custody of the install root is a precondition, checked once and never repaired.** Every guarantee here reduces to one claim: the artifact activated came out of an archive matching the pinned digest. The digest is checked once, on bytes in flight, and from then on the claim rests entirely on nobody else being able to write into the tree. So the library verifies that before it fetches anything — the root and every directory above it, on both the path as written and the path it resolves to, must be owned by you or root and writable by nobody else; the version directory and every entry in it get the same questions at publish and at activation, because a file's mode is independent of its directory's — and it _refuses_ rather than fixing what it finds. A library that quietly chmods a directory it thought too permissive has overruled the operator who configured it and told nobody.
- **Access-control lists are read, not guessed at.** A POSIX mode is a lossy projection of an ACL, and the loss runs the unsafe way: a directory reading `0755 root:root` can carry an entry granting a named user full write. So when a path carries one, it is parsed — POSIX.1e and NFSv4 — and the identities it actually grants write to are what get judged. That turns "there is an ACL here, I decline" into "uid 3000 can write this", which is a sentence an operator can act on. `TrustedUIDs` and `TrustedGIDs` are how you answer it: an identity that is already privileged on the host, an administrator reaching the volume over NFS who holds root anyway, gains nothing by writing these files, and saying so keeps the check enforcing everywhere else. `InstallWithoutCustody` remains for a volume with nothing precise to say about it — one whose filesystem does not make the mode its access decision at all.
- **The verified archive never has a name.** It is created inside the install root and unlinked before the first byte arrives, and the same descriptor carries those bytes through the digest check and into the extraction. There is nothing to point at another file, nothing to rewrite by path, no temp directory whose permissions matter, no `TMPDIR` in the threat surface, and nothing left behind if the process dies mid-download. The unpacker is handed a reader over that descriptor and an `os.Root` on the destination, so an archive entry that names its way out is refused by the kernel rather than by a lexical check that has to be written correctly. A custom unpacker is ordinary Go code and can still go around the root; what the parameters remove is the need to get containment right, not the ability to opt out of it.
- **A sentinel is not proof.** It is a plain file, so it is forgeable rather than evidence — which is why custody above is the defence and not the sentinel's own permissions. Before a version is activated its primary artifact is also probed and must answer with the version its own directory claims. An artifact replaced on the volume under an intact sentinel is excluded, which falls through to another complete version and leaves the pin unsatisfied so the next pass reinstalls.
- **A failed install is survivable.** Every complete version already on the volume keeps serving. Pruning runs only after a successful publish, because those directories _are_ the fallback set. Retries are bounded, and a repair made in place is picked up by `Rescan` without restarting your process.

## Install

`go get github.com/cplieger/pinstall/v2@latest`

## Usage

A `Release` is everything true of the package, independent of where it runs — write it once. A `Config` is one deployment of it: the pin, the digests, the root and your local policy.

```go
package main

import (
	"context"
	"log"
	"os/exec"

	"github.com/cplieger/pinstall/v2"
)

// The pinned digests. Whatever bumps your version literal bumps these with it.
const (
	widgetVersion = "1.4.2"
	amd64SHA      = "9f2b...64 lowercase hex characters..."
	arm64SHA      = "3ce1...64 lowercase hex characters..."
)

// The profile: written once, reused by every deployment.
func widgetRelease() pinstall.Release {
	return pinstall.Release{
		Name:        "widget",
		URLTemplate: "https://widgets.example/dl/{arch}/widget_{version}.zip",
		ArchTokens:  map[string]string{"amd64": "linux-64", "arm64": "linux-arm"},
		ArtifactDir: "dist/bin", // the archive already holds the artifacts
		ProbeArgs:   []string{"--version"},
		Mandatory: []pinstall.Assertion{
			// Must hold after every install; a deployment cannot drop it.
			{Name: "autoupdate", Args: []string{"config", "set", "autoupdate", "off"}},
		},
	}
}

func main() {
	mgr, err := pinstall.New(&pinstall.Config{
		Release: widgetRelease(),
		Version: widgetVersion,
		Digests: map[string]string{"amd64": amd64SHA, "arm64": arm64SHA},
		Root:    "/var/lib/example/tools",
		LinkDir: "bin",                     // optional convenience symlink
		Require: []string{"widget-helper"}, // artifacts you cannot run without
	})
	if err != nil {
		log.Fatal(err)
	}

	// Bounded, retrying, and non-fatal: a failure leaves your program running.
	if err := mgr.EnsureWithRetry(context.Background()); err != nil {
		log.Printf("widget install failed, serving degraded: %v", err)
	}

	if ready, why := mgr.Ready(); !ready {
		log.Printf("widget is not usable yet: %s", why)
		return
	}

	// Always the absolute version-directory path, never the convenience link.
	out, err := exec.Command(mgr.Path(), "run").Output()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", out)
}
```

The library writes only under `Root`:

```text
<Root>/
├── <Name>-versions/
│   ├── 1.4.2/            # the active version: artifacts + .complete
│   └── 1.4.1/            # the retained predecessor
├── <Name>-state.json     # a diagnostic record; never an input to Ready
└── bin/<Binary>          # the optional convenience symlink
```

## Configuration reference

### Release — the package profile

| Field          | Description                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `Name`         | The package identity. Fixes the versions root and the state file. Required                                             |
| `Binary`       | The primary artifact's file name: what gets probed, linked, and always required. Empty defaults to `Name`              |
| `URLTemplate`  | The archive URL, carrying `{version}` and `{arch}`. Required                                                           |
| `ArchTokens`   | `GOARCH` to the publisher's token (`"amd64"` to `"x86_64-linux"`). An unmapped architecture is `ErrUnsupportedArch`    |
| `ProbeArgs`    | The argv that makes the primary artifact print its version. Required                                                   |
| `ParseVersion` | Parses the probe's output. Nil uses `LastFieldOfFirstLine`                                                             |
| `Unpack`       | Extracts the verified archive: an open `*io.SectionReader` over it, into an `os.Root`. Nil uses `UnpackZip`            |
| `Installer`    | An installer script shipped inside the archive. Nil means the archive already holds the artifacts                      |
| `ArtifactDir`  | Where the artifacts land: relative to the installer's private home when `Installer` is set, else to the extracted tree |
| `Mandatory`    | Assertions a deployment cannot configure away. At least one is required — see below                                    |
| `Notice`       | Logged once per install attempt, for a licence acknowledgement the upstream requires                                   |

### Config — one deployment

| Field                   | Description                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `Release`               | The profile above                                                                                                              |
| `Version`               | The pin, constrained to a path- and URL-safe character set                                                                     |
| `Digests`               | `GOARCH` to the lowercase hex SHA-256 of that architecture's archive. The running architecture needs one                       |
| `Root`                  | The absolute installation root; the only tree touched                                                                          |
| `GOARCH`                | Overrides the architecture. Empty resolves from `runtime.GOARCH`                                                               |
| `URLTemplate`           | Overrides the release's template, for a mirror                                                                                 |
| `Require`               | Artifacts a version directory must hold to count as complete. The primary artifact is always added                             |
| `Optional`              | Artifacts installed when the archive provides them, warned about when it does not                                              |
| `Assert`                | Assertions re-asserted on every pass. `Release.Mandatory` is merged in                                                         |
| `Purge`                 | A one-shot sweep of a layout a previous installer left behind. Nil skips it                                                    |
| `LinkDir`               | A directory under `Root` for the convenience symlink. Empty publishes none                                                     |
| `Retain`                | Predecessors kept besides the active version. Zero uses 1                                                                      |
| `RetryBackoff`          | The first `EnsureWithRetry` backoff, doubling to a ten minute cap. Zero uses 30s                                               |
| `MaxAttempts`           | Bounds `EnsureWithRetry`. Zero uses 4                                                                                          |
| `TrustedUIDs`           | Identities whose write access to the tree does not invalidate custody, beyond root and yourself                                |
| `TrustedGIDs`           | The group half of `TrustedUIDs`, and the weaker claim: a group grant reaches every current and future member                   |
| `InstallWithoutCustody` | Install even though custody could not be established. Implies `Untrusted`, and re-authorises the library's own housekeeping    |
| `Untrusted`             | Activate only versions this process installed, whatever the custody check concluded. Costs a verified reinstall on every start |

### Manager

| Method                       | Description                                                                   |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `Ensure(ctx) error`          | One idempotent pass: purge, prune partials, select, install if needed, assert |
| `EnsureWithRetry(ctx) error` | `Ensure` with bounded exponential backoff. Never exits the process            |
| `Rescan(ctx) (bool, error)`  | Re-derive from disk, download nothing. Makes an in-place repair observable    |
| `Ready() (bool, Reason)`     | The verdict, and why it is withheld                                           |
| `Active() (State, bool)`     | The diagnostic record, and whether a version is active                        |
| `PathEntry() string`         | The directory to lead `PATH` with, or `""`                                    |
| `PathEnv() []string`         | That directory as a `PATH=` overlay for `os.Environ()`, or `nil`              |
| `Path() string`              | The absolute primary artifact, or `""`                                        |

`Reason` is an enum, not a message: `ReasonReady`, `ReasonInstalling`, `ReasonRetrying`, `ReasonUnavailable`, `ReasonAssertion`. Your program owns the wording it shows its own users; the library owns only the distinction. Typed errors for classification: `ErrDigestMismatch`, `ErrUnsupportedArch`, `ErrNoVersion`, `ErrVersionMismatch`, `ErrNoCustody`, `ErrACLUnreadable`.

## Assertions, and why one is mandatory

An `Assertion` is a bounded command run against the installed artifact — the full argv after the artifact's path, so the library needs to know nothing about how your package is configured. Required assertions run twice: against the _staged_ artifact before publication, so a candidate they cannot hold on never becomes a version directory, and against the _active_ artifact on every pass, because an assertion's effect usually lives in the package's own mutable configuration and cannot be remembered. A required failure withholds readiness; anything else only warns.

`Release.Mandatory` is the set a deployment cannot weaken, reword or drop: whatever a caller passes, each one is forced Required and substituted with the profile's own argv. **A profile that declares none is refused at construction.** The most common thing to assert is that the package will not update itself — a self-replacing binary invalidates the digest you verified — and "this package needs no post-install guarantee" is indistinguishable from "the profile author forgot". A package that genuinely needs no gate declares its cheapest positive check instead, which makes it a claim someone had to write on purpose.

## Included profiles

`pinstall` names no vendor. A ready-made profile for one release ships alongside it:

- `pinstall/kirocli` — the [kiro-cli](https://kiro.dev) release: URL shape, architecture tokens, in-archive installer, probe argv, licence notice, and the auto-update assertion. Also `kirocli.Setting(key, bool)` / `kirocli.SettingRaw(key, value)` for building assertions in that package's own settings grammar.

```go
mgr, err := pinstall.New(&pinstall.Config{
	Release: kirocli.Release(),
	Version: version,
	Digests: map[string]string{"amd64": amd64SHA, "arm64": armSHA},
	Root:    toolsDir,
	LinkDir: "bin",
	Assert:  []pinstall.Assertion{kirocli.Setting("telemetry.enabled", false)},
})
```

The pin stays with the consumer, so whatever bumps your version and digests keeps working unchanged.

## Sweeping a previous installer's layout

If your program used to install the same package a different way, `Config.Purge` removes what that installer left behind — once per volume, recorded by a marker file. It is injected rather than built in, because the residue is a fact about one deployment's history, not about the package.

Every target is removed only when what is on disk has the _shape_ the old installer left there: a declared artifact must be a regular file, a staging tree must be a directory. A directory holding a convenience link is often co-owned, and another installer publishes symlinks there; a symlink at a swept path is somebody else's live pointer and is refused rather than deleted. Deletes are confined by `os.Root`, so a redirected entry cannot reach outside `Root`. A target that could not be removed withholds the marker, so the next pass retries instead of recording a job it did not finish.

## Unsupported by Design

Deliberate non-goals, not TODOs:

| Not included                                   | Rationale                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signature or attestation verification          | The trust anchor is the digest you pinned, which you obtained out of band. Verify a signature where you produce the pin, not where you consume it                                                                                                                                                                                                                                                                                                                                                                               |
| Per-artifact digests re-verified at activation | Tempting, and it would catch silent corruption, but the digest would be one this library computed itself and stored in the same tree as the artifact. Against the only attacker left after the custody check — one who can write there — the record is exactly as forgeable as the binary, so it would buy a stronger-sounding claim rather than a stronger one. Making it mandatory would also delete every existing version directory on upgrade, and making it optional would be a gate that skips when its input is missing |
| Repairing permissions it finds wrong           | Custody is verified and refused, never fixed. `chmod` on someone else's directory is an authority this library does not have, forcing an exact mode would _widen_ a tree a stricter umask had narrowed, and the operator who set the permission would never learn the library disagreed                                                                                                                                                                                                                                         |
| Resolving "latest"                             | A resolved version is not a pin. Whatever bumps your version and digest literals owns that decision; this library installs exactly what it was told                                                                                                                                                                                                                                                                                                                                                                             |
| Rollback, journals, backups                    | Nothing is ever overwritten in place, so there is no partial-promotion window to recover from. The retained predecessor _is_ the recovery mechanism                                                                                                                                                                                                                                                                                                                                                                             |
| Archive formats beyond zip                     | One `Unpacker` is shipped and tested. A `tar.gz` consumer supplies a function, reading the verified archive from the `*io.SectionReader` and writing through the `os.Root` it is handed; an enum with one implemented value would be a partially built public surface                                                                                                                                                                                                                                                           |
| Windows and macOS                              | The publish protocol relies on same-filesystem rename plus `fsync` of a directory, and the confined deletes use `os.Root`. Linux only, like the rest of this account's libraries                                                                                                                                                                                                                                                                                                                                                |
| Live in-process version upgrades               | Retention assumes a new pin arrives by restarting the consumer. Enabling live upgrades would require per-version leases before a directory could be pruned                                                                                                                                                                                                                                                                                                                                                                      |

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
conventions and how to run the checks locally.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

GPL-3.0. See [LICENSE](LICENSE).
