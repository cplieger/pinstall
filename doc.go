// Package pinstall installs, activates and maintains a digest-pinned upstream
// release.
//
// The unit of installation is <Root>/<Name>-versions/<version>/. It is
// populated only from a digest-verified archive, published by a single
// same-filesystem rename, and marked by a ".complete" sentinel written LAST —
// so an interrupted install is detectable by absence of the sentinel and never
// becomes a selection candidate. Nothing at all is placed under Root before the
// archive digest matches the pin.
//
// Every start re-probes the artifact it is about to activate, re-asserts the
// caller's assertions against it, retains N predecessors and reports a readiness
// verdict. Nothing here exits the process, reads the environment, or performs
// work at import time: a failed install is returned or logged so the caller's
// own surfaces stay alive and the installation can be repaired in place.
//
// A caller builds a [Release] once (everything true of the package, independent
// of any deployment), then one [Config] per deployment (the pin, the digests,
// the root and the local policy), then calls [New]:
//
//	mgr, err := pinstall.New(&pinstall.Config{
//		Release: myprofile.Release(),
//		Version: "1.4.2",
//		Digests: map[string]string{"amd64": amd64SHA256, "arm64": arm64SHA256},
//		Root:    "/var/lib/example/tools",
//	})
//	if err != nil {
//		return err
//	}
//	if err := mgr.EnsureWithRetry(ctx); err != nil {
//		log.Printf("install failed, serving degraded: %v", err)
//	}
//	if ready, why := mgr.Ready(); !ready {
//		return fmt.Errorf("not ready: %s", why)
//	}
//	cmd := exec.CommandContext(ctx, mgr.Path(), "--help")
//
// Durability, version selection, retry, retention and the readiness verdict are
// the library's and are deliberately not configurable. What varies between
// packages is data: the URL shape, the architecture tokens, the in-archive
// installer, the probe argv, the assertions.
//
// Linux only. The publish protocol relies on same-filesystem rename and fsync
// of a directory, and the confined deletes use os.Root.
package pinstall
