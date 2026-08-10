package pinstall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
)

// The extended attributes through which Linux exposes an access-control list. Only a
// NON-trivial ACL creates one, so a path with none is fully described by its mode.
const (
	xattrPOSIXACL = "system.posix_acl_access"
	xattrNFS4ACL  = "system.nfs4_acl"     // the nfs client
	xattrNFS4XDR  = "system.nfs4_acl_xdr" // OpenZFS on Linux
)

// aclXattrs is the order [writersOf] looks for an ACL. POSIX.1e first because it is the
// common case on an ordinary Linux volume.
var aclXattrs = []string{xattrPOSIXACL, xattrNFS4ACL, xattrNFS4XDR}

// principalKind distinguishes the three things an ACL entry can name.
type principalKind uint8

const (
	principalUser principalKind = iota
	principalGroup
	principalEveryone
)

// principal is an identity that can modify a filesystem object. A user or group carries
// its numeric id; everyone carries none.
type principal struct {
	id   int
	kind principalKind
}

func (p principal) String() string {
	switch p.kind {
	case principalUser:
		return fmt.Sprintf("uid %d", p.id)
	case principalGroup:
		return fmt.Sprintf("gid %d", p.id)
	}
	return "everyone"
}

// POSIX.1e access ACL, as encoded in system.posix_acl_access. The layout is stable
// kernel ABI (uapi/linux/posix_acl_xattr.h): a version word, then fixed-size entries.
// Explicitly little-endian on every architecture, because the kernel declares the
// fields as __le32 and __le16.
const (
	posixACLVersion    = 2
	posixACLHeaderSize = 4
	posixACLEntrySize  = 8
	posixACLMaxEntries = 4096 // a sanity bound; real ACLs hold a handful
)

// POSIX.1e entry tags and permission bits.
const (
	posixTagUserObj  uint16 = 0x01
	posixTagUser     uint16 = 0x02
	posixTagGroupObj uint16 = 0x04
	posixTagGroup    uint16 = 0x08
	posixTagMask     uint16 = 0x10
	posixTagOther    uint16 = 0x20

	posixPermWrite uint16 = 0x02
)

// NFSv4 ACL, as encoded in system.nfs4_acl_xdr by OpenZFS. Big-endian XDR: a flags
// word, an entry count, then fixed-size entries of
// {type, flag, whoIsSpecial, accessMask, id}.
//
// The layout and every field below were confirmed against real ACLs read from a ZFS
// nfsv4 dataset, cross-checked bit for bit against nfs4xdr_getfacl's rendering of the
// same objects. acl_golden_test.go carries those samples as fixtures.
const (
	nfs4HeaderSize = 8
	nfs4ACESize    = 20
	nfs4MaxACEs    = 4096
)

// NFSv4 ACE types, flags, special principals and access-mask bits (RFC 7530 §6.2.1).
const (
	nfs4TypeAllow uint32 = 0

	nfs4FlagIdentifierGroup uint32 = 0x0040
	nfs4FlagInheritOnly     uint32 = 0x0008

	nfs4WhoOwner    uint32 = 1
	nfs4WhoGroup    uint32 = 2
	nfs4WhoEveryone uint32 = 3

	nfs4WriteData   uint32 = 0x00000002
	nfs4AppendData  uint32 = 0x00000004
	nfs4DeleteChild uint32 = 0x00000040
	nfs4Delete      uint32 = 0x00010000
	nfs4WriteACL    uint32 = 0x00040000
	nfs4WriteOwner  uint32 = 0x00080000
)

// nfs4WriteMask is every access-mask bit that lets a principal change what this object
// IS, as opposed to reading it or touching its timestamps.
//
// WRITE_ACL and WRITE_OWNER are in the set even though neither writes a byte: a
// principal who can rewrite the ACL can grant itself the rest, and one who can take
// ownership can then do anything. Excluded on purpose: WRITE_ATTRIBUTES (timestamps)
// and WRITE_NAMED_ATTRS (extended attributes), neither of which can replace the
// artifact this library executes.
const nfs4WriteMask = nfs4WriteData | nfs4AppendData | nfs4DeleteChild |
	nfs4Delete | nfs4WriteACL | nfs4WriteOwner

// ErrACLUnreadable reports that an access-control list is present but could not be
// evaluated. It is deliberately distinct from a refusal on the CONTENT of an ACL: this
// one says the check does not know, which is why it fails closed.
var ErrACLUnreadable = errors.New("the access-control list could not be evaluated")

// writersOf returns every principal that can modify path, beyond nothing.
//
// The mode is the floor: its group and other write bits name the object's group and
// everyone. When the object also carries an access-control list, that list is PARSED and
// its grants are added, because a mode is a lossy projection of one — under NFSv4 a
// directory reading 0755 can carry an entry giving a named user full write, which is the
// case that motivated reading the list rather than refusing on its mere presence.
//
// The owner is deliberately NOT included. Every caller checks ownership separately and
// has more to say about it than this function does.
func writersOf(path string, fi os.FileInfo, stat *syscall.Stat_t) ([]principal, error) {
	var out []principal
	perm := fi.Mode().Perm()
	if perm&0o020 != 0 {
		out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
	}
	if perm&0o002 != 0 {
		out = append(out, principal{kind: principalEveryone})
	}
	name, blob, err := readACL(path)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return out, nil
	}
	granted, err := parseACL(name, blob, stat)
	if err != nil {
		return nil, fmt.Errorf("%w: %s holds %s: %w", ErrACLUnreadable, path, name, err)
	}
	return append(out, granted...), nil
}

// readACL returns the name and contents of the first access-control list attribute path
// carries, or "" when it carries none.
//
// A filesystem without extended-attribute support answers ENOTSUP or ENODATA, which
// genuinely means there is no list to read. Every other error is returned: reading the
// list is part of establishing custody, so "I could not look" must not read as "there was
// nothing there".
func readACL(path string) (name string, blob []byte, err error) {
	for _, candidate := range aclXattrs {
		found, readErr := getxattrAll(path, candidate)
		switch {
		case readErr == nil:
			return candidate, found, nil
		case errors.Is(readErr, syscall.ENODATA), errors.Is(readErr, syscall.ENOTSUP),
			errors.Is(readErr, syscall.EOPNOTSUPP), errors.Is(readErr, syscall.ENOSYS):
			continue
		default:
			return "", nil, fmt.Errorf("%w: reading %s of %s: %w", ErrACLUnreadable, candidate, path, readErr)
		}
	}
	return "", nil, nil
}

// getxattrAll reads an attribute whose size it does not know in advance, asking the
// kernel for the length rather than guessing and silently truncating.
func getxattrAll(path, attr string) ([]byte, error) {
	size, err := getxattrFn(path, attr, nil)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, syscall.ENODATA
	}
	buf := make([]byte, size)
	n, err := getxattrFn(path, attr, buf)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		return nil, fmt.Errorf("the attribute grew from %d to %d bytes while being read", size, n)
	}
	return buf[:n], nil
}

// getxattrFn is syscall.Getxattr, replaced in tests: no ordinary test process can mount
// a filesystem that serves an NFSv4 ACL, and that dialect drives the branch this
// package most needs covered.
var getxattrFn = syscall.Getxattr

// parseACL dispatches on the attribute name.
func parseACL(name string, blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	switch name {
	case xattrPOSIXACL:
		return parsePOSIXACL(blob)
	case xattrNFS4ACL, xattrNFS4XDR:
		return parseNFS4ACL(blob, stat)
	}
	return nil, fmt.Errorf("unknown access-control list dialect %q", name)
}

// parsePOSIXACL returns the principals a POSIX.1e access ACL grants write to, other than
// the owner.
//
// The mask is the whole subtlety: it is the ceiling on every named user, every named
// group and the owning group, so an entry granting rwx under an r-x mask grants no write
// at all. That is also why the mode alone is sufficient for this dialect — the mode's
// group bits ARE the mask — but the list is parsed anyway rather than trusted to agree,
// because "these two always match" is exactly the kind of assumption this whole check
// exists to stop making.
func parsePOSIXACL(blob []byte) ([]principal, error) {
	entries, err := decodePOSIXACL(blob)
	if err != nil {
		return nil, err
	}
	// The mask has to be known before the maskable entries can be judged, and it may
	// appear after them in the list, which is why decoding and judging are two passes.
	mask := uint16(0xFFFF)
	for _, e := range entries {
		if e.tag == posixTagMask {
			mask = e.perm
		}
	}
	var out []principal
	for _, e := range entries {
		if e.perm&mask&posixPermWrite == 0 {
			continue
		}
		switch e.tag {
		case posixTagUser:
			out = append(out, principal{kind: principalUser, id: int(e.id)})
		case posixTagGroup:
			out = append(out, principal{kind: principalGroup, id: int(e.id)})
		}
	}
	return out, nil
}

// decodePOSIXACL reads the entries out of a POSIX.1e access ACL, refusing any shape that
// is not exactly a version word followed by whole entries. A short read here would
// under-report writers, which is the one direction this whole check must not fail in.
func decodePOSIXACL(blob []byte) ([]posixEntry, error) {
	if len(blob) < posixACLHeaderSize {
		return nil, fmt.Errorf("%d bytes is shorter than the %d byte header", len(blob), posixACLHeaderSize)
	}
	if v := binary.LittleEndian.Uint32(blob[:posixACLHeaderSize]); v != posixACLVersion {
		return nil, fmt.Errorf("unsupported version %d", v)
	}
	body := blob[posixACLHeaderSize:]
	if len(body)%posixACLEntrySize != 0 {
		return nil, fmt.Errorf("%d bytes of entries is not a multiple of %d", len(body), posixACLEntrySize)
	}
	count := len(body) / posixACLEntrySize
	if count > posixACLMaxEntries {
		return nil, fmt.Errorf("%d entries is over the %d limit", count, posixACLMaxEntries)
	}
	out := make([]posixEntry, 0, count)
	for i := range count {
		raw := body[i*posixACLEntrySize : (i+1)*posixACLEntrySize]
		e := posixEntry{
			tag:  binary.LittleEndian.Uint16(raw[0:2]),
			perm: binary.LittleEndian.Uint16(raw[2:4]),
			id:   binary.LittleEndian.Uint32(raw[4:8]),
		}
		switch e.tag {
		case posixTagUserObj, posixTagUser, posixTagGroupObj, posixTagGroup,
			posixTagMask, posixTagOther:
		default:
			return nil, fmt.Errorf("unknown entry tag %#x", e.tag)
		}
		out = append(out, e)
	}
	return out, nil
}

// posixEntry is one decoded POSIX.1e access-control entry.
type posixEntry struct {
	id   uint32
	tag  uint16
	perm uint16
}

// parseNFS4ACL returns the principals an NFSv4 ACL grants write to, other than the owner.
//
// Only ALLOW entries are read. A DENY entry can only ever subtract, so ignoring them is
// the conservative direction: the worst it does is name a principal that turns out to be
// denied elsewhere, which costs a refusal rather than granting one.
//
// An INHERIT_ONLY entry is skipped because it does not apply to this object at all — it
// exists to be copied onto things created inside it. The objects it will be copied onto
// are checked when they are reached.
func parseNFS4ACL(blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	if len(blob) < nfs4HeaderSize {
		return nil, fmt.Errorf("%d bytes is shorter than the %d byte header", len(blob), nfs4HeaderSize)
	}
	count := binary.BigEndian.Uint32(blob[4:8])
	if count > nfs4MaxACEs {
		return nil, fmt.Errorf("%d entries is over the %d limit", count, nfs4MaxACEs)
	}
	body := blob[nfs4HeaderSize:]
	if want := int(count) * nfs4ACESize; len(body) != want {
		return nil, fmt.Errorf("%d entries need %d bytes of body, got %d", count, want, len(body))
	}

	var out []principal
	for i := range int(count) {
		raw := body[i*nfs4ACESize : (i+1)*nfs4ACESize]
		aceType := binary.BigEndian.Uint32(raw[0:4])
		flag := binary.BigEndian.Uint32(raw[4:8])
		special := binary.BigEndian.Uint32(raw[8:12])
		mask := binary.BigEndian.Uint32(raw[12:16])
		id := binary.BigEndian.Uint32(raw[16:20])

		if aceType != nfs4TypeAllow || flag&nfs4FlagInheritOnly != 0 || mask&nfs4WriteMask == 0 {
			continue
		}
		switch {
		case special == 0:
			kind := principalUser
			if flag&nfs4FlagIdentifierGroup != 0 {
				kind = principalGroup
			}
			out = append(out, principal{kind: kind, id: int(id)})
		case id == nfs4WhoOwner:
			// The owner, which the caller checks itself.
		case id == nfs4WhoGroup:
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		case id == nfs4WhoEveryone:
			out = append(out, principal{kind: principalEveryone})
		default:
			return nil, fmt.Errorf("entry %d names unknown special principal %d", i, id)
		}
	}
	return out, nil
}

// trustedWriters is the set of identities whose write access to the installation tree the
// caller has declared acceptable, resolved once at construction from [Config.TrustedUIDs]
// and [Config.TrustedGIDs].
//
// It exists because "nobody else may write here" is too strong a rule for real
// deployments and too weak a vocabulary for the operator to correct. A volume reached over
// NFS by an administrator who already holds root through sudo grants that account nothing
// new by letting it write, and refusing the whole tree over it helps nobody. What the
// library cannot do is DISCOVER that fact: it can see that uid 3000 may write, never that
// uid 3000 is already privileged. So the operator supplies the identities and the library
// supplies the enumeration, which is the half each is actually able to do.
//
// Root and this process's own uid are always trusted and are not listed here.
type trustedWriters struct {
	uids []int
	gids []int
}

// allowsOwner reports whether an object owned by uid may be part of the tree.
func (t trustedWriters) allowsOwner(uid, euid int) bool {
	return uid == euid || uid == 0 || slices.Contains(t.uids, uid)
}

// allows reports whether p is an identity the caller declared acceptable, or one that is
// always acceptable.
//
// Everyone is never acceptable. A grant to everyone cannot be narrowed by naming
// identities, because it does not name one — declaring it trusted would be declaring the
// check off, and [Config.InstallWithoutCustody] is the honest way to say that.
func (t trustedWriters) allows(p principal, euid int) bool {
	switch p.kind {
	case principalUser:
		return p.id == euid || p.id == 0 || slices.Contains(t.uids, p.id)
	case principalGroup:
		// The root group is trusted for the same reason root is: its only member is
		// already able to do anything this check could stop.
		return p.id == 0 || slices.Contains(t.gids, p.id)
	}
	return false
}

// firstStranger returns the first writer the caller has not accounted for.
func (t trustedWriters) firstStranger(writers []principal, euid int) (principal, bool) {
	for _, p := range writers {
		if !t.allows(p, euid) {
			return p, true
		}
	}
	return principal{}, false
}

// hint appends the pointer to the knob that would resolve the refusal, but only when the
// caller has not already used it — repeating the suggestion to someone who has clearly
// read it just makes the real problem harder to find.
func (t trustedWriters) hint() string {
	if len(t.uids) > 0 || len(t.gids) > 0 {
		return ""
	}
	return ". If that identity is already privileged on this host, declare it in Config.TrustedUIDs or Config.TrustedGIDs"
}
