// Package kirocli is the [pinstall] profile for the kiro-cli release.
//
// It exists so that every consumer installing kiro-cli states the same facts
// about it — the release host and archive shape, the architecture tokens, the
// in-archive installer, the probe argv, the licence notice and the assertion the
// integrity story depends on — exactly once. A profile duplicated per consumer is
// a drift surface: the copies diverge silently, and the one that matters is
// whichever consumer was updated last.
//
// The pin itself is NOT here. The version and the per-architecture digests belong
// to the deployment (and to whatever bumps them), so a consumer passes them in
// [pinstall.Config]:
//
//	mgr, err := pinstall.New(&pinstall.Config{
//		Release: kirocli.Release(),
//		Version: version,
//		Digests: map[string]string{"amd64": amd64SHA256, "arm64": arm64SHA256},
//		Root:    toolsDir,
//		LinkDir: "bin",
//		Assert:  []pinstall.Assertion{kirocli.Setting("telemetry.enabled", false)},
//	})
package kirocli

import (
	"strconv"
	"time"

	"github.com/cplieger/pinstall/v3"
)

// Name is the package identity and the name of its primary artifact.
const Name = "kiro-cli"

// autoUpdateSetting is the one setting the integrity story depends on: with
// auto-update live the binary can replace itself and invalidate the verified
// digest, so [Release] declares it Mandatory and no deployment can drop it.
//
// It is typed rather than an untyped string constant, which changes nothing at the
// call site (an untyped constant converts implicitly) and everything about what the
// declaration says: this package's own key is a [SettingKey] like every key a
// consumer passes.
const autoUpdateSetting SettingKey = "app.disableAutoupdates"

// urlTemplate is the published archive URL. The version is pinned rather than a
// floating "latest" so a given deployment is reproducible and the digest check is
// meaningful.
const urlTemplate = "https://desktop-release.q.us-east-1.amazonaws.com/{version}/kirocli-{arch}.zip"

// licenceNotice is logged once per install attempt. kiro-cli is proprietary
// third-party content that is downloaded at run time rather than redistributed,
// so the acceptance has to be visible where the download happens.
const licenceNotice = "kiro-cli is proprietary AWS Content; by installing it you accept the AWS Customer Agreement at https://kiro.dev/license/"

// Release returns the kiro-cli profile. Each call returns a fresh value, so a
// consumer can adjust it without affecting any other consumer in the process.
//
// The required set is deliberately left to the caller beyond the main dispatcher:
// which sidecars a deployment cannot run without is a property of what that
// deployment does with kiro-cli, not of the release.
func Release() pinstall.Release {
	return pinstall.Release{
		Name:        Name,
		URLTemplate: urlTemplate,
		ArchTokens: map[string]string{
			"amd64": "x86_64-linux",
			"arm64": "aarch64-linux",
		},
		Installer: &pinstall.ArchiveInstaller{
			Path:    "kirocli/install.sh",
			Args:    []string{"--no-confirm"},
			Timeout: 120 * time.Second,
		},
		ArtifactDir: ".local/bin",
		ProbeArgs:   []string{"--version"},
		Notice:      licenceNotice,
		Mandatory:   []pinstall.Assertion{Setting(autoUpdateSetting, true)},
	}
}

// SettingKey names a kiro-cli setting (the dotted form: "app.disableAutoupdates",
// "chat.notificationMethod"). It is a distinct type so the key and a string
// VALUE cannot be transposed in a SettingRaw call — a swapped call wrote the
// wrong setting under the wrong key, silently, since both sides are strings on
// the wire. An untyped string constant still converts implicitly at a call
// site; the type guards every site that passes variables.
type SettingKey string

// Setting returns the assertion that sets a boolean kiro-cli setting.
//
// The `settings <key> <value>` grammar is package knowledge, which is why it
// lives here rather than as a hook in pinstall: the library takes a full argv and
// needs to know nothing about how kiro-cli is configured.
func Setting(key SettingKey, value bool) pinstall.Assertion {
	return SettingRaw(key, strconv.FormatBool(value))
}

// SettingRaw returns the assertion that sets a kiro-cli setting to a verbatim
// string value, for the settings whose value is not a boolean.
func SettingRaw(key SettingKey, value string) pinstall.Assertion {
	return pinstall.Assertion{Name: string(key), Args: []string{"settings", string(key), value}}
}

// ShellEraDispatchers returns the dispatcher names a shell-era kiro-cli installer
// promoted into a shared bin directory, for [pinstall.Purge]'s Names. It is a
// function rather than a variable so a caller cannot mutate the list another
// caller is about to sweep with.
//
// The set is fixed on purpose. Sweeping by a `kiro-cli*` prefix instead would
// delete every matching entry in a directory this package does not own — including
// another installer's live symlink of the same name.
func ShellEraDispatchers() []string {
	return []string{Name, Name + "-chat", Name + "-term"}
}
