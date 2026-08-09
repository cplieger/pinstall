package pinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNewValidatesItsPins pins construction: a manager cannot exist without a
// version, an absolute root, a supported architecture and a well-formed digest
// for THAT architecture. Rejecting a mangled pin at construction beats
// discovering it after a large download.
func TestNewValidatesItsPins(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Config)
		wantErr string
	}{
		"missing version":       {mutate: func(c *Config) { c.Version = "" }, wantErr: "Version"},
		"traversal version":     {mutate: func(c *Config) { c.Version = "../../etc" }, wantErr: "Version"},
		"separator in version":  {mutate: func(c *Config) { c.Version = "2.14.2/x" }, wantErr: "illegal character"},
		"dotted version":        {mutate: func(c *Config) { c.Version = ".hidden" }, wantErr: "dot"},
		"missing root":          {mutate: func(c *Config) { c.Root = "" }, wantErr: "Root is required"},
		"relative root":         {mutate: func(c *Config) { c.Root = "tools" }, wantErr: "must be absolute"},
		"no digests at all":     {mutate: func(c *Config) { c.Digests = nil }, wantErr: "Digests is required"},
		"no digest for arch":    {mutate: func(c *Config) { delete(c.Digests, "amd64") }, wantErr: "no pinned digest"},
		"unsupported arch":      {mutate: func(c *Config) { c.GOARCH = "sparc64" }, wantErr: "no published archive"},
		"truncated digest":      {mutate: func(c *Config) { c.Digests["amd64"] = sixtyFourHexChars[:63] }, wantErr: "64 hex"},
		"non-hex digest":        {mutate: func(c *Config) { c.Digests["amd64"] = strings.Repeat("z", 64) }, wantErr: "hexadecimal"},
		"uppercase digest":      {mutate: func(c *Config) { c.Digests["amd64"] = strings.ToUpper(sixtyFourHexChars) }, wantErr: "lowercase"},
		"other arch digest bad": {mutate: func(c *Config) { c.Digests["arm64"] = "junk" }},
		"absolute link dir":     {mutate: func(c *Config) { c.LinkDir = "/usr/local/bin" }, wantErr: "must be relative"},
		"escaping link dir":     {mutate: func(c *Config) { c.LinkDir = "../bin" }, wantErr: "escape"},
		"artifact with a slash": {mutate: func(c *Config) { c.Require = []string{"sub/tool"} }, wantErr: "single path component"},
		"dotted artifact":       {mutate: func(c *Config) { c.Require = []string{".complete"} }, wantErr: "must not start with a dot"},
		"bad url override":      {mutate: func(c *Config) { c.URLTemplate = "ftp://x/{version}" }, wantErr: "http or https"},
		"url without version":   {mutate: func(c *Config) { c.URLTemplate = "https://x/fixed.zip" }, wantErr: "{version}"},
		"valid":                 {mutate: func(*Config) {}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			cfg := env.config(tc.mutate)
			m, err := New(cfg)
			switch {
			case tc.wantErr == "":
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				if m.cfg.MaxAttempts <= 0 || m.cfg.RetryBackoff <= 0 || m.cfg.Retain <= 0 || m.urlTemplate == "" {
					t.Errorf("New left a default unset: attempts=%d backoff=%v retain=%d url=%q",
						m.cfg.MaxAttempts, m.cfg.RetryBackoff, m.cfg.Retain, m.urlTemplate)
				}
			case err == nil:
				t.Fatalf("New accepted %s", name)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewRejectsAConfigPointerOfNil pins the one input that cannot be validated
// field by field.
func TestNewRejectsAConfigPointerOfNil(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) returned no error")
	}
}

// TestNewCopiesEverythingItDependsOn pins that a caller mutating its own Config
// after construction cannot change what the manager installs. The maps and slices
// in a Config are shared by a shallow copy, so the facts have to be resolved once.
func TestNewCopiesEverythingItDependsOn(t *testing.T) {
	env := newFakeEnv(t)
	cfg := env.config()
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wantURL := m.archiveURL()
	wantRequire := append([]string(nil), m.cfg.Require...)

	cfg.Digests["amd64"] = strings.Repeat("f", 64)
	cfg.Require[0] = "hijacked"
	cfg.Release.ArchTokens["amd64"] = "hijacked"
	cfg.Version = "9.9.9"

	if m.digest != env.digest {
		t.Errorf("digest = %q, want the digest resolved at construction %q", m.digest, env.digest)
	}
	if got := m.archiveURL(); got != wantURL {
		t.Errorf("archiveURL() = %q, want %q", got, wantURL)
	}
	for i, name := range wantRequire {
		if m.cfg.Require[i] != name {
			t.Errorf("Require[%d] = %q, want %q", i, m.cfg.Require[i], name)
		}
	}
}

// TestNewRefusesAProfileWithNoMandatoryAssertions pins the guarantee that cannot
// be lost by omission. A package's integrity gate becomes profile DATA in this
// library, and a profile with an empty Mandatory set is indistinguishable from one
// whose author forgot — so construction refuses rather than shipping a silently
// ungated install.
func TestNewRefusesAProfileWithNoMandatoryAssertions(t *testing.T) {
	tests := map[string]struct {
		mandatory []Assertion
		wantErr   string
	}{
		"nil":             {mandatory: nil, wantErr: "Mandatory is empty"},
		"empty slice":     {mandatory: []Assertion{}, wantErr: "Mandatory is empty"},
		"no name":         {mandatory: []Assertion{{Args: []string{"x"}}}, wantErr: "has no Name"},
		"no args":         {mandatory: []Assertion{{Name: "a"}}, wantErr: "has no Args"},
		"duplicate names": {mandatory: []Assertion{{Name: "a", Args: []string{"x"}}, {Name: "a", Args: []string{"y"}}}, wantErr: "two assertions named"},
		"one is enough":   {mandatory: []Assertion{{Name: "a", Args: []string{"x"}}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			_, err := New(env.config(func(c *Config) { c.Release.Mandatory = tc.mandatory }))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("New: %v", err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("New accepted a profile with %s", name)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestMandatoryAssertionsCannotBeWeakened pins the merge: whatever a deployment
// passes, every mandatory assertion is present exactly once, is Required, and
// carries the profile's argv rather than the caller's.
func TestMandatoryAssertionsCannotBeWeakened(t *testing.T) {
	mandatory := []Assertion{
		{Name: "gate", Args: []string{"settings", "gate", "true"}},
		{Name: "other", Args: []string{"settings", "other", "on"}},
	}
	tests := map[string][]Assertion{
		"no caller assertions":      nil,
		"unrelated caller":          {{Name: "telemetry", Args: []string{"settings", "telemetry", "false"}}},
		"redeclared not required":   {{Name: "gate", Args: []string{"settings", "gate", "true"}}},
		"redeclared with a lie":     {{Name: "gate", Args: []string{"settings", "gate", "false"}}},
		"redeclared twice":          {{Name: "gate", Args: []string{"x"}}, {Name: "gate", Args: []string{"y"}}},
		"redeclared with a no-op":   {{Name: "gate", Args: []string{"help"}}},
		"both redeclared, reversed": {{Name: "other", Args: []string{"no"}}, {Name: "gate", Args: []string{"no"}}},
	}
	for name, caller := range tests {
		t.Run(name, func(t *testing.T) {
			got := mergeAssertions(caller, mandatory)
			for _, want := range mandatory {
				seen := 0
				for _, a := range got {
					if a.Name != want.Name {
						continue
					}
					seen++
					if !a.Required {
						t.Errorf("%s is not Required after the merge", a.Name)
					}
					if strings.Join(a.Args, " ") != strings.Join(want.Args, " ") {
						t.Errorf("%s args = %v, want the profile's %v", a.Name, a.Args, want.Args)
					}
				}
				if seen != 1 {
					t.Errorf("%s appears %d times, want exactly 1", want.Name, seen)
				}
			}
			for _, a := range caller {
				if a.Name == "telemetry" && !hasAssertion(got, "telemetry") {
					t.Error("an unrelated caller assertion was dropped by the merge")
				}
			}
		})
	}
}

func hasAssertion(as []Assertion, name string) bool {
	for _, a := range as {
		if a.Name == name {
			return true
		}
	}
	return false
}

// TestEnsureReassertsRequiredAssertionsOnAStartThatSkipsTheInstall pins that an
// assertion cannot be remembered. Its effect lives in the package's own mutable
// configuration, not in the immutable version directory, so even the fast path
// where the pinned directory is already complete must re-prove it against the
// selected artifact — and a failure there withholds readiness rather than warning.
func TestEnsureReassertsRequiredAssertionsOnAStartThatSkipsTheInstall(t *testing.T) {
	t.Run("asserted without downloading anything", func(t *testing.T) {
		env := newFakeEnv(t)
		dir := env.placeVersion(pinnedVersion)
		m := env.manager(func(c *Config) {
			c.Assert = []Assertion{{Name: "telemetry.enabled", Args: []string{"settings", "telemetry.enabled", "false"}}}
		})

		if err := m.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if env.fetchCount() != 0 {
			t.Errorf("fetches = %d, want 0 on a start that already has the pin", env.fetchCount())
		}
		want := "assert settings " + mandatoryName + " true on " + filepath.Join(dir, toolName)
		if env.countCalls(want) != 1 {
			t.Errorf("calls = %v, want exactly one %q against the SELECTED artifact", env.called(), want)
		}
		if env.countCalls("assert settings telemetry.enabled false") != 1 {
			t.Error("the best-effort assertions were not applied on the skip-install start")
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true", why)
		}
	})

	t.Run("a failed reassertion withholds readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		env.placeVersion(pinnedVersion)
		env.onAssert = failAssertion(mandatoryName)
		m := env.manager()

		err := m.Ensure(context.Background())
		if err == nil || !strings.Contains(err.Error(), mandatoryName) {
			t.Fatalf("Ensure error = %v, want one naming %s", err, mandatoryName)
		}
		ready, why := m.Ready()
		if ready || why != ReasonAssertion {
			t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonAssertion)
		}
		// The artifact stays reachable for repair even though it is not ready.
		if got := m.Path(); got == "" {
			t.Error("Path() is empty; the usable artifact must stay available for an in-place repair")
		}
	})

	t.Run("a best-effort failure does not withhold readiness", func(t *testing.T) {
		env := newFakeEnv(t)
		env.placeVersion(pinnedVersion)
		env.onAssert = failAssertion("chat.notificationMethod")
		m := env.manager(func(c *Config) {
			c.Assert = []Assertion{{Name: "chat.notificationMethod", Args: []string{"settings", "chat.notificationMethod", "osc9"}}}
		})

		if err := m.Ensure(context.Background()); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if ready, why := m.Ready(); !ready {
			t.Errorf("Ready() = false (%s), want true: a best-effort assertion is not integrity-relevant", why)
		}
	})
}

// failAssertion returns an onAssert hook that fails only the assertion whose argv
// mentions name.
func failAssertion(name string) func(string, []string) error {
	return func(_ string, args []string) error {
		if slices.Contains(args, name) {
			return errors.New("the assertion command failed")
		}
		return nil
	}
}

// TestPersistedAssertionsOKNeverGatesReadiness pins that the persisted record is
// diagnostic history only. A state file claiming the assertions held must not make
// a manager whose live reassertion failed report ready.
func TestPersistedAssertionsOKNeverGatesReadiness(t *testing.T) {
	env := newFakeEnv(t)
	dir := env.placeVersion(pinnedVersion)
	seed, err := json.Marshal(State{
		ActiveVersion: pinnedVersion,
		Dir:           dir,
		Pinned:        pinnedVersion,
		AssertionsOK:  true,
		UpdatedAt:     time.Unix(1, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(env.statePath(), seed, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	env.onAssert = failAssertion(mandatoryName)
	m := env.manager()

	if err := m.Ensure(context.Background()); err == nil {
		t.Fatal("Ensure returned nil although a required assertion failed")
	}
	if ready, why := m.Ready(); ready || why != ReasonAssertion {
		t.Errorf("Ready() = (%v, %v), want (false, %v) -- the persisted record must never be the authority",
			ready, why, ReasonAssertion)
	}
	if state, _ := m.Active(); state.AssertionsOK {
		t.Error("State.AssertionsOK stayed true after a failed reassertion; it must record THIS start's result")
	}
}

// TestStateSaveFailureDoesNotAffectReadiness pins that the diagnostic record is
// not on the readiness path: losing it warns, it does not fail an otherwise good
// install.
func TestStateSaveFailureDoesNotAffectReadiness(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	env.onRename = failRenameTo(env.statePath())
	m := env.manager()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure error = %v, want nil despite the state save failure", err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true", why)
	}
}

// failRenameTo returns an onRename hook that fails exactly the rename whose
// destination is target.
func failRenameTo(target string) func(string, string) error {
	return func(_, newpath string) error {
		if newpath == target {
			return errors.New("injected rename failure")
		}
		return nil
	}
}

// TestEnsureWithRetryIsBoundedAndReportsTerminalFailure pins the first half of the
// healing posture: a failing install is retried with growing backoff, the attempts
// are BOUNDED, and the end state is a distinguishable terminal verdict rather than
// an endless loop or a process exit.
func TestEnsureWithRetryIsBoundedAndReportsTerminalFailure(t *testing.T) {
	env := newFakeEnv(t)
	env.installerFails = true
	m := env.manager(func(c *Config) {
		c.MaxAttempts = 3
		c.RetryBackoff = time.Second
	})

	err := m.EnsureWithRetry(context.Background())
	if err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	if got := env.fetchCount(); got != 3 {
		t.Errorf("fetches = %d, want 3 (one per bounded attempt)", got)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if got := env.sleeps(); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("backoffs = %v, want %v (doubling, one fewer than the attempts)", got, want)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}

// TestEnsureWithRetryStopsEarlyOnShutdown pins that a shutdown during the retry
// loop ends it rather than burning the remaining attempts: once on a cancelled
// context, and once when the backoff wait itself reports the cancellation.
func TestEnsureWithRetryStopsEarlyOnShutdown(t *testing.T) {
	t.Run("a cancelled context stops after the attempt in flight", func(t *testing.T) {
		env := newFakeEnv(t)
		env.installerFails = true
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		m := env.manager(func(c *Config) { c.MaxAttempts = 4 })

		if err := m.EnsureWithRetry(ctx); err == nil {
			t.Fatal("EnsureWithRetry returned nil although the install failed")
		}
		if got := env.fetchCount(); got != 1 {
			t.Errorf("fetches = %d, want 1: a cancelled context must not start a second attempt", got)
		}
		if got := env.sleeps(); len(got) != 0 {
			t.Errorf("backoffs = %v, want none on a cancelled context", got)
		}
	})

	t.Run("a wait that reports cancellation is returned", func(t *testing.T) {
		env := newFakeEnv(t)
		env.installerFails = true
		m := env.manager(func(c *Config) { c.MaxAttempts = 4 })
		m.sleep = func(context.Context, time.Duration) error { return context.Canceled }

		err := m.EnsureWithRetry(context.Background())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("EnsureWithRetry error = %v, want context.Canceled", err)
		}
		if got := env.fetchCount(); got != 1 {
			t.Errorf("fetches = %d, want 1: the loop must stop at the cancelled wait", got)
		}
	})
}

// TestReadinessReasonDistinguishesTheLifecyclePhases pins that a caller gating on
// readiness can tell installing from retrying from terminally failed, which is the
// whole reason [Reason] is an enum rather than a bool.
func TestReadinessReasonDistinguishesTheLifecyclePhases(t *testing.T) {
	tests := map[string]struct {
		phase phase
		want  Reason
	}{
		"idle":                     {phase: phaseIdle, want: ReasonInstalling},
		"installing":               {phase: phaseInstalling, want: ReasonInstalling},
		"retrying":                 {phase: phaseRetrying, want: ReasonRetrying},
		"failed":                   {phase: phaseFailed, want: ReasonUnavailable},
		"ready but nothing active": {phase: phaseReady, want: ReasonUnavailable},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newFakeEnv(t)
			m := env.manager()
			m.setPhase(tc.phase)
			ready, why := m.Ready()
			if ready {
				t.Fatal("Ready() = true with no active version")
			}
			if why != tc.want {
				t.Errorf("reason = %v, want %v", why, tc.want)
			}
		})
	}
}

// TestReasonStringIsEmptyOnlyWhenReady pins the one property a consumer builds its
// own wording on: a withheld verdict always has something to say.
func TestReasonStringIsEmptyOnlyWhenReady(t *testing.T) {
	for r := ReasonReady; r <= ReasonAssertion+1; r++ {
		got := r.String()
		if (r == ReasonReady) != (got == "") {
			t.Errorf("Reason(%d).String() = %q; only ReasonReady may be empty", r, got)
		}
	}
}

// TestRescanMakesAnInPlaceRepairVisible pins the second half of the healing
// posture. A first start that fails with nothing to fall back on leaves the
// consumer up and unready; an operator who repairs the install in place must
// become observable without a fresh process.
func TestRescanMakesAnInPlaceRepairVisible(t *testing.T) {
	env := newFakeEnv(t)
	env.installerFails = true
	m := env.manager(func(c *Config) { c.MaxAttempts = 2 })

	if err := m.EnsureWithRetry(context.Background()); err == nil {
		t.Fatal("EnsureWithRetry returned nil although every attempt failed")
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Fatalf("Ready() = (%v, %v), want (false, %v) before the repair", ready, why, ReasonUnavailable)
	}
	before := env.fetchCount()

	// The repair: an operator restores a complete version directory by hand.
	dir := env.placeVersion(pinnedVersion)

	ok, err := m.Rescan(context.Background())
	if err != nil || !ok {
		t.Fatalf("Rescan = (%v, %v), want (true, nil)", ok, err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true after the in-place repair", why)
	}
	if got := m.Path(); got != filepath.Join(dir, toolName) {
		t.Errorf("Path() = %q, want %q", got, filepath.Join(dir, toolName))
	}
	if env.fetchCount() != before {
		t.Errorf("Rescan downloaded the archive (%d -> %d); it must only re-derive from disk", before, env.fetchCount())
	}
	if state, active := m.Active(); !active || state.LastError != "" {
		t.Errorf("State = %+v (active=%v), want the previous failure cleared", state, active)
	}
}

// TestRescanReportsUnreadyWhenTheRepairIsIncomplete pins the negative half: a
// half-restored directory (no sentinel) is not a repair, so Rescan keeps readiness
// withheld instead of activating a partial install.
func TestRescanReportsUnreadyWhenTheRepairIsIncomplete(t *testing.T) {
	env := newFakeEnv(t)
	env.placePartial(pinnedVersion)
	m := env.manager()

	ok, err := m.Rescan(context.Background())
	if ok {
		t.Fatal("Rescan accepted a directory with no completion sentinel")
	}
	if !errors.Is(err, ErrNoVersion) {
		t.Errorf("Rescan error = %v, want ErrNoVersion", err)
	}
	if ready, why := m.Ready(); ready || why != ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, ReasonUnavailable)
	}
}

// TestEnsureIsIdempotent pins that a second Ensure on a converged volume downloads
// nothing, keeps the same active version, and still re-asserts every assertion.
func TestEnsureIsIdempotent(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	first := m.Path()
	afterFirst := env.countCalls("assert settings " + mandatoryName)

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := env.fetchCount(); got != 1 {
		t.Errorf("fetches = %d, want 1 -- the second Ensure must not re-download", got)
	}
	if got := m.Path(); got != first {
		t.Errorf("Path() = %q, want the unchanged %q", got, first)
	}
	if got := env.countCalls("assert settings " + mandatoryName); got <= afterFirst {
		t.Error("the second Ensure did not reassert the required assertion")
	}
}

// TestBackoffDoublesAndCaps pins the retry schedule's shape, including the cap that
// stops a long-lived process from waiting hours between attempts.
func TestBackoffDoublesAndCaps(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager(func(c *Config) { c.RetryBackoff = time.Minute })
	tests := map[int]time.Duration{
		1: time.Minute,
		2: 2 * time.Minute,
		3: 4 * time.Minute,
		4: 8 * time.Minute,
		5: maxRetryBackoff,
		9: maxRetryBackoff,
	}
	for attempt, want := range tests {
		if got := m.backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
}

// TestSleepCtxHonoursCancellation pins that the backoff wait is cancellable, so a
// shutdown during a retry window does not block on a timer.
func TestSleepCtxHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx error = %v, want context.Canceled", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx error = %v, want nil", err)
	}
}

// TestProbeAndAssertionsLeadPATHWithTheBinaryDir pins the sidecar-delegation
// contract: a multi-binary release's primary executable may resolve its
// sidecars by BARE NAME on PATH rather than beside its own executable
// (kiro-cli's `settings` delegates to the kiro-cli-chat sidecar that way).
// Every command pinstall runs against an installed or staged binary must
// therefore lead PATH with that binary's own directory, or every assertion
// fails with ENOENT while the sidecar sits right next to the asserted binary.
func TestProbeAndAssertionsLeadPATHWithTheBinaryDir(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	var mu sync.Mutex
	envsByBin := map[string][]string{}
	inner := m.run
	m.run = func(ctx context.Context, c *command) ([]byte, error) {
		if !env.isInstaller(c.Path) {
			mu.Lock()
			envsByBin[c.Path] = append([]string(nil), c.Env...)
			mu.Unlock()
		}
		return inner(ctx, c)
	}

	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(envsByBin) == 0 {
		t.Fatal("no probe or assertion commands ran; the test proved nothing")
	}
	for bin, cmdEnv := range envsByBin {
		want := "PATH=" + filepath.Dir(bin) + string(os.PathListSeparator)
		var found bool
		for _, kv := range cmdEnv {
			if strings.HasPrefix(kv, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("command against %s ran without its directory leading PATH; env = %v", bin, cmdEnv)
		}
	}
}

// The operation slot has two halves and neither is sufficient alone: WAITING for
// it honours the caller's context, and the work that has been ADMITTED does not.
// Consumers were compensating for the absence of both with their own admission
// gates plus a context.WithoutCancel wrapper, which is library knowledge that
// nothing kept in step (one of two consumers had neither).

// A caller that gives up while queued must return promptly instead of holding a
// goroutine inside the library until an operation it never started finishes.
func TestOperationWaitIsCancellable(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	// Occupy the slot exactly as a running operation would.
	if err := m.acquireOp(context.Background()); err != nil {
		t.Fatalf("acquireOp: %v", err)
	}
	defer m.releaseOp()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.acquireOp(ctx) }()

	// It must still be waiting: the slot is taken.
	select {
	case err := <-done:
		t.Fatalf("acquireOp returned %v while the slot was held", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("acquireOp err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acquireOp did not return after its context was cancelled; the wait is not cancellable")
	}
}

// A queued Rescan whose caller disconnects must not run, and must not disturb the
// manager's state.
func TestRescanQueuedCallerCanAbandon(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	m := env.manager()
	if _, err := m.Rescan(context.Background()); err != nil {
		t.Fatalf("priming Rescan: %v", err)
	}
	readyBefore, _ := m.Ready()

	if err := m.acquireOp(context.Background()); err != nil {
		t.Fatalf("acquireOp: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the caller is already gone

	done := make(chan error, 1)
	go func() {
		_, err := m.Rescan(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Rescan err = %v, want context.Canceled for an abandoned queued caller", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an abandoned queued Rescan never returned")
	}
	m.releaseOp()

	if ready, why := m.Ready(); ready != readyBefore {
		t.Errorf("Ready() = (%v, %v) after an abandoned rescan, want it unchanged (%v)", ready, why, readyBefore)
	}
}

// The half that matters most: an ADMITTED rescan finishes on its own terms. Its
// probes run through exec.CommandContext and a failed probe sweep records the
// release unavailable, so honouring the caller's cancellation here would let a
// `curl --max-time` turn a healthy manager into an unready one.
func TestAdmittedRescanIgnoresCallerCancellation(t *testing.T) {
	env := newFakeEnv(t)
	env.placeVersion(pinnedVersion)
	m := env.manager()

	// Cancelled BEFORE the call, so the detachment is the only thing that can
	// make this succeed: an undetached implementation fails every probe.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := m.Rescan(ctx)
	if err != nil || !ok {
		t.Fatalf("Rescan = (%v, %v) with an already-cancelled caller, want (true, nil): the admitted work must be detached", ok, err)
	}
	if ready, why := m.Ready(); !ready {
		t.Errorf("Ready() = false (%s) after a rescan whose caller had cancelled; the cancellation cleared the active version", why)
	}
}

// Ensure deliberately does NOT detach: it is driven by boot and shutdown, where
// cancelling a long download is exactly what the caller wants. Only the wait
// became cancellable.
func TestEnsureStillHonoursCancellation(t *testing.T) {
	env := newFakeEnv(t)
	m := env.manager()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := m.Ensure(ctx); err == nil {
		t.Fatal("Ensure returned nil for an already-cancelled context; a shutdown could no longer stop an install")
	}
}
