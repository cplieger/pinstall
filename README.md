# pinstall

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/pinstall/v3.svg)](https://pkg.go.dev/github.com/cplieger/pinstall/v3) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/pinstall)](https://github.com/cplieger/pinstall/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/pinstall/badges/mutation.json)](https://github.com/cplieger/pinstall/issues?q=label%3Agremlins-tracker)

pinstall installs a pinned version of another program from your Go code, refuses it unless its SHA-256 matches your pin, and tells your program when it is ready to run.

It replaces the download, checksum and install steps you would otherwise write in a shell script or a container entrypoint. It runs on Linux only, needs Go 1.27.1 or later and is licensed under Apache-2.0. Its one dependency outside the standard library is [pathinside](https://github.com/cplieger/pathinside), which uses only the standard library itself.

## Why use it

pinstall is built for a long-running Linux program, often a container, that downloads another vendor's binary at run time. A typical case is a tool whose license lets you download it but not include it in your image.

- Nothing reaches a version directory until the archive's SHA-256 matches your pin.
- Each version installs into its own directory and is marked complete last, so an interrupted install is never used.
- On every start it checks the binary's version and reruns your required setup commands, such as turning auto-update off.
- It keeps one earlier version by default as a fallback, retries with bounded backoff and never exits your process.
- By default it refuses an install tree that an account other than yours, root's or one you list can write to, and names the path and the account. `InstallWithoutCustody` turns that refusal into a warning.

Consider [aqua](https://aquaproj.github.io/) if you want to pin CLI tool versions per project in a config file, for development and CI on Windows, macOS and Linux.

## Install

```sh
go get github.com/cplieger/pinstall/v3@latest
```

## Usage

A `Release` describes the package and is written once. A `Config` is one deployment of it, with the pin, the digests, the install root and your local policy.

```go
package main

import (
	"context"
	"log"
	"os/exec"

	"github.com/cplieger/pinstall/v3"
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

Run the binary at `mgr.Path()`. Put `mgr.PathEntry()` first in the `PATH` of anything you start. You can instead append `mgr.PathEnv()` to `os.Environ()`. Either way, a program that looks up this release's artifacts by name finds the active version.

Each digest is the SHA-256 of that architecture's archive, which you record when you choose the version. pinstall downloads with its own HTTP client, which reads no proxy settings from the environment. `Config.URLTemplate` can point at a mirror instead.

The `pinstall/kirocli` package is a ready-made `Release` for [kiro-cli](https://kiro.dev/cli/), Kiro's terminal coding agent. [Configuration](docs/configuration.md) lists every field and its default.

## API

- `New` checks a `Release` and a `Config` and returns a `*Manager`. It refuses a release that declares no mandatory assertion.
- `Ensure` runs one idempotent install pass, `EnsureWithRetry` retries it with backoff, and `Rescan` rereads the disk without downloading.
- `Ready`, `Active`, `Path`, `PathEntry` and `PathEnv` report readiness and where the active binary is.
- `Reason` is one of `ReasonReady`, `ReasonInstalling`, `ReasonRetrying`, `ReasonUnavailable` and `ReasonAssertion`. Your program chooses the words it shows for each.
- `ErrDigestMismatch`, `ErrUnsupportedArch`, `ErrNoVersion`, `ErrVersionMismatch`, `ErrNoCustody`, `ErrACLUnreadable` and `ErrACLDialectUnsupported` match with `errors.Is`.
- `UnpackZip` and `LastFieldOfFirstLine` are the default unpacker and version parser. `ParseIdentities` parses a list of trusted user or group IDs. It reports how many entries it refused, never their text, so a secret set on the wrong variable stays out of your logs.

A `Manager` logs installs, retries and warnings through the default `log/slog` logger. pinstall reads no environment variable for its own settings and does no work at import time. The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/pinstall/v3).

## What it guarantees

- A version directory is complete or absent. Each file is synced, a `.complete` marker is written and synced last, and only then is the directory renamed into place.
- The install root stays private. Before anything is fetched, the root and every directory above it must be owned by you or root and writable by nobody else, access-control lists included.
- It refuses an unsafe tree and leaves the fix to you. When another account that can write the tree already holds root, such as an administrator, list it in `TrustedUIDs` or `TrustedGIDs`.
- The verified archive cannot be swapped. Its file name is deleted before the first byte arrives, and extraction reads the same open file the digest check read.
- Names it acts on stay under `Root`. Archive entries, moved artifacts, the state record, the link and every sweep target go through an `os.Root`, so the kernel refuses a symlink that would redirect one.
- Required settings hold on every start. Each `Mandatory` assertion runs against the staged binary before publication and against the active one on every pass, and a failure withholds readiness.
- A failed install keeps the old version serving. Pruning runs only after a successful publish.

The ownership check has two exemptions. A directory above the root may be writable by others when its sticky bit is set, as on `/tmp`. Group 0 counts as trusted, so the check does not guard against an account that belongs to group 0. [How pinstall works](docs/how-it-works.md) has the full contract.

## Unsupported by design

- Signature or attestation checks. Your pinned digest is the trust anchor, so check a signature where you produce the pin.
- Resolving "latest". It installs exactly the version it is given.
- Repairing permissions it finds wrong. It refuses and names the path.
- Rollback journals and backups. Nothing is overwritten in place, and the kept predecessor is the recovery.
- Archive formats other than zip. For a `tar.gz` release, write an `Unpacker`, one function that receives the verified bytes and an `os.Root` on the destination. Staying inside that root is your code's job.
- Windows and macOS.
- Changing the version inside a running process. A new pin arrives by restarting your program.

[Non-goals](docs/non-goals.md) gives the reasoning for each, and for leaving out per-file digest checks at activation.

## Documentation

- [Configuration](docs/configuration.md) lists every `Release` and `Config` field, its default, and how retention and trusted identities work.
- [How pinstall works](docs/how-it-works.md) covers the install protocol, the ownership check, assertions, downloads and the sweep of an older install layout.
- [Non-goals](docs/non-goals.md) explains what is left out and why.

## Credits

The ownership check verifies once and refuses, as OpenSSH's [StrictModes](https://man.openbsd.org/sshd_config#StrictModes), sudo's [ownership check on sudoers](https://www.sudo.ws/docs/man/sudoers.man/) and git's [safe.directory](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory) do.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
