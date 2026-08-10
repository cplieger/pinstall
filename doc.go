// Package pinstall installs, activates and maintains a digest-pinned upstream
// release.
//
// The unit of installation is <Root>/<Name>-versions/<version>/. It is
// populated only from a digest-verified archive, published by a single
// same-filesystem rename, and marked by a ".complete" sentinel written LAST —
// so an interrupted install is detectable by absence of the sentinel and never
// becomes a selection candidate.
//
// Custody of that tree is the precondition everything else rests on, verified
// before any byte is fetched and never repaired: Root and every directory above
// it must be modifiable only by this process's identity or root. See
// [ErrNoCustody]. The verified archive itself is unlinked before the first byte
// arrives and reaches the unpacker as a reader on that same descriptor, so it has
// no name to substitute, and the unpacker writes through an [os.Root] on the
// extraction directory, so no archive entry can escape it.
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
// Linux only. The publish protocol relies on same-filesystem rename and fsync of
// a directory, the confined writes and deletes use os.Root, and the custody check
// reads Unix ownership plus the extended attributes through which a filesystem
// exposes an access-control list.
package pinstall
