package pinstall

import "errors"

// Errors callers can classify. Everything else is wrapped with context.
var (
	// ErrDigestMismatch reports that the downloaded archive is not the artifact
	// the pinned digest names. Nothing is placed under Root when it is returned.
	ErrDigestMismatch = errors.New("archive SHA-256 mismatch")
	// ErrUnsupportedArch reports an architecture the release publishes no
	// archive for, or one with no pinned digest.
	ErrUnsupportedArch = errors.New("unsupported architecture")
	// ErrNoVersion reports that no complete version is installed and none could
	// be installed, so there is nothing to activate.
	ErrNoVersion = errors.New("no complete version is installed")
	// ErrVersionMismatch reports that a candidate artifact answered the version
	// probe with something other than the version its directory and sentinel
	// claim.
	ErrVersionMismatch = errors.New("binary reported a version its install directory does not claim")
	// ErrNoCustody reports that the installation root, or a directory on the way
	// to it, can be modified by a principal other than this process's identity or
	// root — so nothing installed there can be trusted to stay what was
	// installed. The wrapped text names the offending path and what is wrong with
	// it. Fix the volume, or set [Config.Untrusted] to proceed anyway.
	ErrNoCustody = errors.New("the installation root is not under this process's exclusive control")
)
