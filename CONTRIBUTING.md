# Contributing to pinstall

The [shared rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) for commits, releases, synced files and checks apply here.

## Rules

- A function field on `Release` is only for a shape with no universal form, like `ParseVersion` and `Unpack`. Anything else that varies per package is plain data.
- A check on a new `Release` or `Config` field belongs in `Release.validate` or `Config.validate`, so `New` refuses a bad profile before any download. The field also needs a row in `docs/configuration.md` and a test.
- Clone every new map, slice or pointer reachable from `Config` in `Config.snapshot`, including fields under `Release.Installer`. Otherwise a caller can change validated behavior after `New` returns.
- A new boundary seam is an unexported field on `Manager`, replaced in `fakeEnv.wire` in `harness_test.go` in the same change, or every test runs the real boundary.
- New parsing or validation of untrusted input gets a `testing.F` target that asserts a real invariant. A panic-only target passes a parser that accepts bad input.

## Checks

- Run the suite as a non-root user before you push. A test whose assertion depends on the uid or gid it runs as will pass in a root container and fail in CI, which runs unprivileged.
- A test that skips without root gates nothing in CI, so add one beside it that runs unprivileged. Use your own primary gid as the stranger group unless it is 0, or call `allowsOwner` and `checkSymlink` directly with any identity.
- Mutation-check a new security predicate as that non-root user. Break it and confirm a test fails. A mutant that survives there is a guard CI does not hold.
