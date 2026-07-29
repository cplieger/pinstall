# Contributing to pinstall

Notes on the install protocol, the parameter model, and the test suite. The
durability protocol and the "nothing app-specific in the core" rule are the point
of the library, so most of this guide is about preserving them.

## What the library is

`pinstall` installs a digest-pinned upstream release into a version-addressed
directory, activates it, and reports whether the result is usable. It has no
dependencies outside the standard library, and it is Linux-only: the publish
protocol relies on a same-filesystem rename plus `fsync` of a directory, and every
delete is confined by `os.Root`.

Five invariants are load-bearing. A change that weakens one is a breaking change
even if the API is untouched.

- **The durability protocol, in order.** Write each artifact, `fsync` each one,
  write and `fsync` the `.complete` sentinel LAST, `fsync` the staged directory,
  rename it into place, `fsync` the installation root. Any sync failure fails the
  install. Do not reorder these, do not batch them, and do not treat the rename as
  sufficient: atomic visibility is not crash durability.
- **Nothing reaches `Root` before the digest matches.** The archive is downloaded
  and verified in a process-local temp dir; the staging tree is created only
  afterwards. `TestEnsureDigestMismatchPlacesNothing` asserts the empty root.
- **A sentinel is not proof.** `selectActive` probes every candidate's primary
  artifact and requires it to answer with the version its own directory claims.
  Do not add a fast path that trusts the sentinel alone.
- **A failed install prunes nothing.** `pruneSuperseded` runs only after a
  successful publish, because the versions on the volume are the fallback set.
- **The readiness verdict comes from THIS process's assertions.** `State` is
  diagnostic; `State.AssertionsOK` is history. `Ready` reads the in-memory flag
  that only a live assertion sets. Do not make any persisted field an input.

## The parameter model

The core package names no vendor and carries no upstream's facts. When you need a
behaviour that varies per package, the order of preference is:

1. **Data on `Release` or `Config`** — a string, a slice, a map. Most things are
   this: the URL template, the architecture tokens, the probe argv, the artifact
   names, the assertions.
2. **A nil-defaultable function field** — only where the shape genuinely has no
   universal form (`ParseVersion`) or where an enum with one implemented value
   would be a partially built public surface (`Unpack`).
3. **Nothing** — where one strategy exists and no consumer differs on it. The
   private-staging-home approach is deliberately not a knob; `Installer.HomeEnv`
   plus `ArtifactDir` is all the genericity it needs.

Two rules that follow from that:

- **Every exported parameter must be exercised by a test.** The suite carries a
  second, deliberately different profile (`widget_test.go`: no in-archive
  installer, a package name that differs from its binary, a JSON version probe,
  two required artifacts, no link dir, no purge, retention of two) driven end to
  end for exactly this reason, plus tables for `ArtifactDir`'s two meanings and
  each off switch asserted by absence. A new parameter with no test is not done.
- **New validation belongs in `New`.** A profile is written once and reused by
  every deployment, so a mistake in it must be reported at construction rather
  than after a large download. `Release.validate` and `Config.validate` own that.

`Release.Mandatory` may not become optional. It is the mechanism that keeps a
package's own integrity gate from being lost when it becomes profile data, and an
empty set is indistinguishable from a forgetful profile author.

## Layout

Flat, one concept per file:

| File          | Owns                                                                      |
| ------------- | ------------------------------------------------------------------------- |
| `doc.go`      | the package documentation                                                 |
| `pinstall.go` | `Config`, `Manager`, `New`, the lifecycle, `Reason`, `State`, validation  |
| `release.go`  | `Release`, `ArchiveInstaller`, `Assertion`, `Purge`, and their validation |
| `install.go`  | fetch, digest verification, staging, assembly, the publish protocol       |
| `unpack.go`   | `Unpacker`, `UnpackZip`, `safeJoin`                                       |
| `versions.go` | completeness, the version probe, selection, ordering, retention, pruning  |
| `purge.go`    | the one-shot sweep and the convenience link                               |
| `errors.go`   | the sentinel errors                                                       |
| `kirocli/`    | one shipped profile; the core must never import it                        |

Every boundary the manager crosses — the archive fetch, subprocess execution,
`fsync`, `rename`, the clock, the sleep — is an unexported struct field on
`Manager`, replaced wholesale by the test harness. They stay unexported: a
consumer configures behaviour through `Release` and `Config`, not by substituting
the filesystem. Add a seam only when a real failure path cannot otherwise be
reached, and wire it into `fakeEnv` in the same change.

## Local development

The module targets the Go version pinned in `go.mod`. Use that toolchain or newer.

```sh
go build ./...
go test ./...
go test -race ./...
```

### Linting and formatting

Lint config lives in `.golangci.yaml` (golangci-lint v2): `gosec`, `gocritic`,
`revive`, `gocyclo`, `gocognit`, `sloglint` (kv-only), `govet` with every
analyser including `fieldalignment`, and others. Formatting is `gofumpt`
(`extra-rules`) plus `gci` import grouping; `golangci-lint run` reports
unformatted files as issues, so format before pushing.

```sh
golangci-lint run
golangci-lint fmt
```

`fieldalignment` is why the exported config structs put a trailing slice last and
`Manager` carries an explained `//nolint` — its field order documents which lock
guards what, which is worth more than the bytes.

### Mutation testing

`.gremlins.yaml` configures [Gremlins](https://gremlins.dev) mutation testing
(synced from `cplieger/ci`; change it upstream). Run it locally to confirm new
tests actually kill mutants:

```sh
gremlins unleash .
```

## Test suite conventions

The core tests are in-package (`package pinstall`) because they replace the
manager's seams; `example_test.go` and the `kirocli` tests are external, so they
exercise the surface a consumer sees. Match the file to the unit:

- `harness_test.go`: `fakeEnv` — the double for every boundary, the in-memory zip
  builders, and the fixtures that plant complete or partial version directories.
  It is profile-driven, so the same harness runs any test profile.
- `pinstall_test.go`: construction validation, the mandatory-assertion refusal and
  merge, reassertion on a start that skips the install, the diagnostic record, the
  bounded retry loop, the readiness reasons, `Rescan`, and idempotence.
- `install_test.go`: the happy path, the digest refusal, per-architecture digest
  selection, a sync failure at every point of the durability protocol, the publish
  boundary, the staged gates, the `Installer == nil` axis, `ArtifactDir`'s two
  meanings, the `Unpacker` seam's contract, and the fetch boundary.
- `versions_test.go`: every incomplete directory shape, partial pruning, a
  replaced artifact under an intact sentinel, the `Untrusted` contract, the
  retention table across every `Retain` value, and version ordering.
- `purge_test.go`: the injected sweep, the shape refusals, idempotence and
  resumption, the marker's two jobs, the off switches, and the convenience link.
- `unpack_test.go`: the zip-slip guards positively and negatively, mode handling,
  and the size budget.
- `release_test.go`: the profile and sweep validation tables, the package-name
  versus artifact-name separation, and the pin validator.
- `widget_test.go`: the synthetic second profile, end to end.

Conventions that matter here:

- Set `RetryBackoff` to a millisecond in retry tests; the harness records the
  backoffs it was asked to sleep, so assert the schedule rather than the wall
  clock.
- Assert observable behaviour: the published directory's contents, the recorded
  boundary crossings, the readiness reason, the typed error via `errors.Is`. An
  off switch is asserted by ABSENCE (no link, no marker, no directory created).
- Every untrusted string boundary carries a `testing.F` target with a real
  invariant, not a crash-only body: `FuzzSafeJoin` (an accepted archive entry
  resolves strictly inside the extraction directory), `FuzzValidateVersion` (an
  accepted pin is one benign path component and carries no URL metacharacter), and
  `FuzzLastFieldOfFirstLine` (the result is always a whitespace-free field of the
  first line). Add one for any new parsing or validation you introduce.
- A case that only passes unprivileged (a permission-denied delete) skips
  explicitly when running as root rather than asserting something weaker.

## Commits and PRs

Branch from `main`, keep changes focused with tests, and open a PR. This account
uses [Conventional Commits](https://www.conventionalcommits.org/) parsed by
git-cliff (`cliff.toml`), so the commit type drives the version bump: `feat:`,
`fix:`, `sec:`, and `chore:`/`docs:`/`refactor:`/`test:` (no release). Write the
subject as the changelog line a consumer would read.

## Conduct & security

By participating you agree to the org-wide
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report security issues through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md),
never in a public issue.
