# Configuration

This page lists every field of `Release` and `Config`, with its default, for a developer writing a profile or a deployment. The generated reference on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/pinstall/v3) carries the full doc comments.

A `Release` is everything true of the package wherever it runs, so you write it once. A `Config` is one deployment of it. `New` checks both and reports a mistake before anything is downloaded.

## Release fields

| Field | Description |
| --- | --- |
| `Name` | Required. The package identity. It names the versions directory and the state file. |
| `Binary` | The primary artifact's file name, which is probed, linked and always required. Empty uses `Name`. |
| `URLTemplate` | Required. The archive URL, with `{version}` and `{arch}` placeholders. |
| `ArchTokens` | Maps a `GOARCH` to the publisher's token, such as `"amd64"` to `"x86_64-linux"`. An unmapped architecture is `ErrUnsupportedArch`. |
| `ProbeArgs` | Required. The arguments that make the primary artifact print its version. They must only query, because retention runs them too. |
| `ParseVersion` | Reads the version from the probe's output. Nil uses `LastFieldOfFirstLine`. |
| `Unpack` | Extracts the verified archive from an `*io.SectionReader` into an `os.Root`. Nil uses `UnpackZip`. |
| `Installer` | An installer script shipped inside the archive. Nil means the archive already holds the artifacts. |
| `ArtifactDir` | Where the artifacts land. It is relative to the installer's private home with an `Installer`, otherwise to the extracted tree, and must stay inside it. |
| `Mandatory` | Required, at least one. Assertions a deployment cannot weaken, reword or drop. See [Assertions](how-it-works.md#assertions). |
| `Notice` | Logged once per install attempt, for a license acknowledgement the upstream requires. |

## Config fields

| Field | Description | Default |
| --- | --- | --- |
| `Release` | The profile above. | required |
| `Version` | The pin, limited to characters that are safe in a path and in a URL. | required |
| `Digests` | Maps a `GOARCH` to the lowercase hex SHA-256 of that architecture's archive. The running architecture needs an entry. | required |
| `Root` | The absolute install root. It is the only tree pinstall reads, writes or deletes. | required |
| `GOARCH` | Overrides the architecture. | `runtime.GOARCH` |
| `URLTemplate` | Overrides the release's template, for a mirror. | the release's template |
| `Require` | Artifacts a version directory must hold to count as complete. The primary artifact is always included. | _(unset)_ |
| `Optional` | Artifacts installed when the archive has them, with a warning when it does not. | _(unset)_ |
| `Assert` | Assertions run again on every pass. `Release.Mandatory` is merged in. | _(unset)_ |
| `Purge` | A one-shot sweep of a layout an earlier installer left. Nil skips it. See [the sweep](how-it-works.md#sweeping-an-earlier-installers-layout). | _(unset)_ |
| `LinkDir` | A directory under `Root` for a convenience symlink. Empty, or a directory that resolves outside `Root`, publishes none. | _(unset)_ |
| `Retain` | Predecessors kept besides the active version. See [Retention](#retention). | 1 |
| `RetryBackoff` | The first `EnsureWithRetry` wait. It doubles on each attempt, up to 10 minutes. | 30s |
| `MaxAttempts` | The number of attempts `EnsureWithRetry` makes. | 4 |
| `TrustedUIDs` | User IDs whose write access to the tree does not break custody, beyond root and the running user. | _(unset)_ |
| `TrustedGIDs` | The group form of `TrustedUIDs`. It is the weaker claim, because it covers every current and future member of the group. | _(unset)_ |
| `InstallWithoutCustody` | Installs even when custody fails, and allows pinstall's own cleanup in that tree. It implies `Untrusted`. | false |
| `Untrusted` | Activates only versions this process installed, whatever the custody check found. It costs a verified reinstall on every start. | false |

A zero `Retain`, `RetryBackoff` or `MaxAttempts` uses the default.

## Retention

A predecessor counts towards `Retain` only when version selection would activate it. A corrupt newer directory therefore never pushes out a good older one, which matters most when the new pin has already failed.

A predecessor that cannot serve is handled by the reason it cannot:

- Under a clean custody verdict with `Untrusted` set, a version an earlier process installed can never be activated, so pruning removes it. `Retain` bounds the tree under a clean verdict whether or not `Untrusted` is set.
- When custody refused the tree and `InstallWithoutCustody` waived the refusal, a complete directory may be another user's install. pinstall neither counts it nor deletes it. The tree then grows by one directory per upgrade until something outside pinstall removes them.
- A directory that fails the version probe, or holds an entry that is not private to this process, is left as found and not counted.

## Trusted identities

The custody check can see that uid 3000 may write the tree. It cannot tell that uid 3000 is an administrator who already holds root, so writing those files gains that account nothing. `TrustedUIDs` and `TrustedGIDs` are how you say so, and the check keeps enforcing the rule for everyone else.

Each entry is a claim that the identity is already at least as privileged as the process running the install. The unprivileged account your application runs as is not, and listing it defeats the check. "Everyone" cannot be listed, because a grant to everyone names no identity. For a volume with nothing precise to declare, `InstallWithoutCustody` is the waiver.

`ParseIdentities(raw string) (ids []int, rejected int)` turns a comma-separated list of numeric identities into the shape both fields take. It reads no environment variable and logs nothing, so you own the variable's name and every word an operator reads about it.

It returns a count of refused entries rather than the entries. A mis-wired deployment can put a credential on any variable, and echoing what was refused would put a copy of that secret in your logs. The count is enough to say that some of the list did not apply.

It refuses text that is not a number, `0` and any negative value. Root is trusted unconditionally, so naming it grants nothing. A blank between commas is skipped rather than counted, so a trailing comma declares no identity. Duplicates collapse, and first-seen order is kept.

```go
uids, rejected := pinstall.ParseIdentities(os.Getenv("MYAPP_TRUSTED_UIDS"))
if rejected > 0 {
    slog.Warn("ignoring unusable MYAPP_TRUSTED_UIDS entries",
        "count", rejected,
        "hint", "each entry is one numeric uid above 0, already at least as privileged as this process")
}
cfg.TrustedUIDs = uids
```

## The kiro-cli profile

The core package names no vendor. `pinstall/kirocli` is a ready-made profile for the [kiro-cli](https://kiro.dev/cli/) release. It sets the URL shape, the architecture tokens, the in-archive installer, the probe arguments, the license notice and the assertion that turns auto-update off.

`kirocli.Setting(key, bool)` and `kirocli.SettingRaw(key, value)` build assertions in kiro-cli's own settings syntax. Both take a `kirocli.SettingKey` rather than a `string`, so a key and a string value cannot be swapped in a `SettingRaw` call. A string literal converts on its own, and a variable has to be declared as a `SettingKey`.

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

The pin stays with your program, so whatever bumps your version and digests keeps working unchanged.
