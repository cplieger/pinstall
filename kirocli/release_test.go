package kirocli_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/pinstall/v2"
	"github.com/cplieger/pinstall/v2/kirocli"
)

const (
	amd64Digest = "1111111111111111111111111111111111111111111111111111111111111111"
	arm64Digest = "2222222222222222222222222222222222222222222222222222222222222222"
)

// config is the shape a consumer builds: the profile from this package, the pin and
// the digests from wherever the consumer keeps them.
func config(mutate ...func(*pinstall.Config)) *pinstall.Config {
	cfg := &pinstall.Config{
		Release: kirocli.Release(),
		Version: "2.14.2",
		Digests: map[string]string{"amd64": amd64Digest, "arm64": arm64Digest},
		Root:    "/config/tools",
		LinkDir: "bin",
	}
	for _, f := range mutate {
		f(cfg)
	}
	return cfg
}

// TestReleaseIsAcceptedByPinstall pins the profile against the library's own
// validation. Every rule pinstall enforces at construction — the identity, the URL
// template, the architecture map, the probe argv, the relative installer path and the
// mandatory assertion — is checked here, so a profile edit that breaks one is caught
// by this package's own suite rather than by a consumer's boot.
func TestReleaseIsAcceptedByPinstall(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		t.Run(goarch, func(t *testing.T) {
			if _, err := pinstall.New(config(func(c *pinstall.Config) { c.GOARCH = goarch })); err != nil {
				t.Fatalf("pinstall.New: %v", err)
			}
		})
	}
}

// TestReleaseDeclaresTheAutoUpdateGateAsMandatory pins the reason this profile exists
// as shared code rather than as a copy per consumer. With auto-update live the binary
// replaces itself and invalidates the digest that was verified, so the assertion that
// switches it off is Mandatory — and no deployment can drop it.
func TestReleaseDeclaresTheAutoUpdateGateAsMandatory(t *testing.T) {
	release := kirocli.Release()
	if len(release.Mandatory) != 1 {
		t.Fatalf("Mandatory = %+v, want exactly the auto-update gate", release.Mandatory)
	}
	got := release.Mandatory[0]
	if got.Name != "app.disableAutoupdates" {
		t.Errorf("mandatory assertion is %q, want app.disableAutoupdates", got.Name)
	}
	want := []string{"settings", "app.disableAutoupdates", "true"}
	if !slices.Equal(got.Args, want) {
		t.Errorf("mandatory argv = %v, want %v", got.Args, want)
	}

	// A deployment that redeclares it with a weaker value must not win.
	cfg := config(func(c *pinstall.Config) {
		c.GOARCH = "amd64"
		c.Assert = []pinstall.Assertion{kirocli.Setting("app.disableAutoupdates", false)}
	})
	if _, err := pinstall.New(cfg); err != nil {
		t.Fatalf("pinstall.New: %v", err)
	}
}

// TestReleaseCarriesTheArchivesRealShape pins the facts a consumer would otherwise
// re-derive from upstream documentation: the release host, the archive file name, the
// two published architecture tokens, and the installer inside the archive.
func TestReleaseCarriesTheArchivesRealShape(t *testing.T) {
	release := kirocli.Release()
	if release.Name != kirocli.Name {
		t.Errorf("Name = %q, want the package constant %q", release.Name, kirocli.Name)
	}
	if kirocli.Name != "kiro-cli" {
		t.Errorf("kirocli.Name = %q, want kiro-cli", kirocli.Name)
	}
	if release.Binary != "" && release.Binary != release.Name {
		t.Errorf("Binary = %q, want it to default to the package name", release.Binary)
	}
	for _, want := range []string{"{version}", "{arch}", ".zip", "https://"} {
		if !strings.Contains(release.URLTemplate, want) {
			t.Errorf("URLTemplate %q does not carry %q", release.URLTemplate, want)
		}
	}
	wantTokens := map[string]string{"amd64": "x86_64-linux", "arm64": "aarch64-linux"}
	for goarch, token := range wantTokens {
		if got := release.ArchTokens[goarch]; got != token {
			t.Errorf("ArchTokens[%s] = %q, want %q", goarch, got, token)
		}
	}
	if len(release.ArchTokens) != len(wantTokens) {
		t.Errorf("ArchTokens = %v, want exactly the published set %v", release.ArchTokens, wantTokens)
	}
	if release.Installer == nil {
		t.Fatal("Installer is nil, but the archive ships an installer rather than bare artifacts")
	}
	if release.Installer.Path != "kirocli/install.sh" {
		t.Errorf("Installer.Path = %q, want kirocli/install.sh", release.Installer.Path)
	}
	if !slices.Equal(release.Installer.Args, []string{"--no-confirm"}) {
		t.Errorf("Installer.Args = %v, want the non-interactive flag", release.Installer.Args)
	}
	if release.Installer.Timeout <= 0 {
		t.Error("Installer.Timeout is unset; a wedged installer must not stall a start forever")
	}
	if release.ArtifactDir != ".local/bin" {
		t.Errorf("ArtifactDir = %q, want .local/bin (relative to the installer's private home)", release.ArtifactDir)
	}
	if !slices.Equal(release.ProbeArgs, []string{"--version"}) {
		t.Errorf("ProbeArgs = %v, want --version", release.ProbeArgs)
	}
	if release.ParseVersion != nil {
		t.Error("ParseVersion is set, but this package's probe prints the default shape")
	}
	if release.Unpack != nil {
		t.Error("Unpack is set, but the archive is a zip, which the library unpacks itself")
	}
}

// TestReleaseCarriesTheLicenceNotice pins that the acceptance a proprietary upstream
// requires travels with the profile, because the download is what triggers it.
func TestReleaseCarriesTheLicenceNotice(t *testing.T) {
	notice := kirocli.Release().Notice
	if notice == "" {
		t.Fatal("Notice is empty; this package is proprietary content downloaded at run time")
	}
	for _, want := range []string{"proprietary", "https://"} {
		if !strings.Contains(notice, want) {
			t.Errorf("Notice %q does not mention %q", notice, want)
		}
	}
}

// TestReleaseIsFreshOnEveryCall pins that two consumers in one process cannot corrupt
// each other's profile, which is why Release is a function returning a value rather
// than a package-level variable.
func TestReleaseIsFreshOnEveryCall(t *testing.T) {
	first := kirocli.Release()
	first.ArchTokens["amd64"] = "hijacked"
	first.Installer.Args[0] = "--hijacked"
	first.Mandatory[0].Args[2] = "false"

	second := kirocli.Release()
	if second.ArchTokens["amd64"] != "x86_64-linux" {
		t.Error("mutating one Release's ArchTokens changed the next one")
	}
	if second.Installer.Args[0] != "--no-confirm" {
		t.Error("mutating one Release's installer args changed the next one")
	}
	if second.Mandatory[0].Args[2] != "true" {
		t.Error("mutating one Release's mandatory assertion changed the next one")
	}
}

// TestSettingBuildsTheConfigGrammar pins the helper that keeps the settings grammar
// out of the library: the full argv is the caller's, so pinstall needs to know nothing
// about how this package is configured.
func TestSettingBuildsTheConfigGrammar(t *testing.T) {
	tests := map[string]struct {
		got  pinstall.Assertion
		want []string
	}{
		"boolean true":  {got: kirocli.Setting("telemetry.enabled", true), want: []string{"settings", "telemetry.enabled", "true"}},
		"boolean false": {got: kirocli.Setting("telemetry.enabled", false), want: []string{"settings", "telemetry.enabled", "false"}},
		"raw value":     {got: kirocli.SettingRaw("chat.notificationMethod", "osc9"), want: []string{"settings", "chat.notificationMethod", "osc9"}},
		"raw empty":     {got: kirocli.SettingRaw("chat.terminalTitle", ""), want: []string{"settings", "chat.terminalTitle", ""}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if !slices.Equal(tc.got.Args, tc.want) {
				t.Errorf("Args = %v, want %v", tc.got.Args, tc.want)
			}
			if tc.got.Name != tc.want[1] {
				t.Errorf("Name = %q, want the setting key %q", tc.got.Name, tc.want[1])
			}
			if tc.got.Required {
				t.Error("a helper-built assertion is Required; only Release.Mandatory may force that")
			}
		})
	}
}

// TestShellEraDispatchersIsAFixedCopy pins the two properties the purge list needs: it
// is the fixed set a shell-era installer promoted (never a prefix sweep of a directory
// this package does not own), and each caller gets its own copy.
func TestShellEraDispatchersIsAFixedCopy(t *testing.T) {
	want := []string{"kiro-cli", "kiro-cli-chat", "kiro-cli-term"}
	got := kirocli.ShellEraDispatchers()
	if !slices.Equal(got, want) {
		t.Fatalf("ShellEraDispatchers() = %v, want %v", got, want)
	}
	got[0] = "hijacked"
	if second := kirocli.ShellEraDispatchers(); second[0] != want[0] {
		t.Error("mutating the returned slice changed what the next caller sees")
	}
}

// TestPurgeBuiltFromTheProfileIsAccepted pins the whole consumer wiring the profile is
// meant to serve: a sweep of the shell-era layout, declared entirely by the consumer,
// with the dispatcher names coming from this package.
func TestPurgeBuiltFromTheProfileIsAccepted(t *testing.T) {
	cfg := config(func(c *pinstall.Config) {
		c.GOARCH = "amd64"
		c.Require = []string{"kiro-cli-chat"}
		c.Optional = []string{"kiro-cli-term"}
		c.Assert = []pinstall.Assertion{
			kirocli.Setting("telemetry.enabled", false),
			kirocli.Setting("chat.enableNotifications", true),
			kirocli.SettingRaw("chat.notificationMethod", "osc9"),
			kirocli.Setting("chat.terminalTitle", false),
		}
		c.Purge = &pinstall.Purge{
			Artifacts:   []string{"bin/.kiro-cli.prev", ".kiro-cli-installed"},
			Names:       kirocli.ShellEraDispatchers(),
			StagePrefix: ".kiro-cli-stage.",
			Marker:      ".kiro-cli-legacy-purged",
		}
	})
	if _, err := pinstall.New(cfg); err != nil {
		t.Fatalf("pinstall.New: %v", err)
	}
}
