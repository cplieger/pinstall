//go:build linux

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
// common case on an ordinary Linux volume. system.nfs4_acl is consulted although no parser
// here decodes it: finding it is what turns an undecodable grant into a refusal that names
// the dialect, rather than a grant nobody looked for. See [ErrACLDialectUnsupported].
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
	nfs4TypeDeny  uint32 = 1
	nfs4TypeAudit uint32 = 2
	nfs4TypeAlarm uint32 = 3

	nfs4FlagIdentifierGroup uint32 = 0x0040
	nfs4FlagInheritOnly     uint32 = 0x0008

	// nfs4WhoIsSpecial is the ONLY discriminator value that makes an ACE's id a
	// special-principal number rather than a uid or gid. It is named because the
	// alternative -- treating "not zero" as "special" -- reads a named id as a
	// special one, and the two answers disagree about who may write. Every ACE in
	// every captured fixture carries 0 or 1.
	nfs4WhoIsSpecial uint32 = 1

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

// nfs4ControlMask is the subset of nfs4WriteMask that lets a principal dismantle an
// object's own protection rather than merely write through it: take the ownership that
// gates chmod and chown, rewrite the list itself, or remove an entry it does not own.
//
// DELETE_CHILD is in the set because it is the sticky rule, not a consequence of it. RFC
// 7530 makes an explicit grant the access decision and leaves the sticky bit as the
// fallback for when the list does not decide, so a named identity holding DELETE_CHILD on
// an ancestor can remove a component this walk has just judged and put its own tree at that
// name — while the mode, on the 1777 ancestor the exemption exists for, already lets it
// create the replacement.
//
// It exists because the sticky exemption is conditional on facts a holder of these bits can
// change. See [controllersOf].
const nfs4ControlMask = nfs4WriteACL | nfs4WriteOwner | nfs4DeleteChild

// ErrACLUnreadable reports that an access-control list is present but could not be
// evaluated. It is deliberately distinct from a refusal on the CONTENT of an ACL: this
// one says the check does not know, which is why it fails closed.
var ErrACLUnreadable = errors.New("the access-control list could not be evaluated")

// ErrACLDialectUnsupported reports that an object carries an access-control list in a
// dialect this package cannot decode, as distinct from one it decoded and refused. It
// wraps [ErrACLUnreadable], because the consequence is the same one: the check does not
// know who can write, so it fails closed.
//
// system.nfs4_acl is the only dialect in this state, and it is worth stating why rather
// than dropping it from the list of attributes consulted. It is the attribute
// nfs4-acl-tools reads and writes, and it carries VARIABLE-LENGTH STRING principals
// ("root@example.com") rather than the numeric ids of the XDR encoding OpenZFS serves
// through system.nfs4_acl_xdr, which is where every list this parser has been checked
// against came from. Decoding the one with the other's fixed-size layout misreads ids
// wherever the lengths happen to line up and skips entries wherever they do not — a
// writer set quietly missing a writer. Ignoring the attribute instead would make a grant
// served over NFS invisible, which is the same failure by omission. So it is named: an
// operator who knows the identities on that export can declare them in
// [Config.TrustedUIDs] and [Config.TrustedGIDs], and one who knows the volume needs no
// checking can say so with [Config.InstallWithoutCustody].
var ErrACLDialectUnsupported = fmt.Errorf("%w: the dialect is not one this parser can decode", ErrACLUnreadable)

// writersOf returns every principal that can modify path, beyond nothing.
//
// The list is read first, because whether the MODE says anything this function should
// believe depends on which dialect the object carries. Where there is no list, and under
// NFSv4 where the mode is an independent projection of one, the mode's group and other
// write bits name the object's group and everyone, and the list's grants are added to
// them — a directory reading 0755 can carry an NFSv4 entry giving a named user full write,
// which is the case that motivated reading the list rather than refusing on its mere
// presence.
//
// Under POSIX.1e the mode is NOT a floor, and reading it as one is a fail-CLOSED bug that
// defeats the whole feature. The mode's group bits are the ACL's MASK there, not the
// GROUP_OBJ grant: on a directory owned root:3000 carrying {u::rwx, u:1234:rwx, g::r-x,
// m::rwx, o::---} the kernel stores mode 0770, and a floor read off it names gid 3000 as a
// writer the list explicitly denies. Nothing the operator can declare clears that, because
// the group they would have to trust provably cannot write. So for that dialect the answer
// comes entirely from [parsePOSIXACL], which names GROUP_OBJ (capped by the mask) and OTHER
// (never capped) in every case, including a list carrying no mask at all.
//
// The owner is deliberately NOT included. Every caller checks ownership separately and
// has more to say about it than this function does.
func writersOf(path string, fi os.FileInfo, stat *syscall.Stat_t) ([]principal, error) {
	name, blob, err := readACL(path)
	if err != nil {
		return nil, err
	}
	var out []principal
	if name != xattrPOSIXACL {
		perm := fi.Mode().Perm()
		if perm&0o020 != 0 {
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		}
		if perm&0o002 != 0 {
			out = append(out, principal{kind: principalEveryone})
		}
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
//
// ENOSYS is on the second side of that line, not the first. It means the getxattr call
// itself did not happen -- an old kernel, or more likely a seccomp filter denying the
// syscall -- so it says nothing whatever about the object. Treating it as absence let a
// sandbox that blocks getxattr produce a clean verdict for a tree an ACL grants a stranger
// write to, which is the sandbox making the check weaker rather than stricter.
//
// A list in a dialect no parser here understands is on that second side too, and refuses
// by name rather than being decoded with a layout that does not fit it. See
// [ErrACLDialectUnsupported].
func readACL(path string) (name string, blob []byte, err error) {
	for _, candidate := range aclXattrs {
		found, readErr := getxattrAll(path, candidate)
		switch {
		case readErr == nil && candidate == xattrNFS4ACL:
			return "", nil, fmt.Errorf("%w: %s holds %s, which carries string principals rather than the numeric ids of %s; name the identities allowed to write it in Config.TrustedUIDs or Config.TrustedGIDs, or waive the check with Config.InstallWithoutCustody",
				ErrACLDialectUnsupported, path, xattrNFS4ACL, xattrNFS4XDR)
		case readErr == nil:
			return candidate, found, nil
		case errors.Is(readErr, syscall.ENODATA), errors.Is(readErr, syscall.ENOTSUP),
			errors.Is(readErr, syscall.EOPNOTSUPP):
			continue
		default:
			return "", nil, fmt.Errorf("%w: reading %s of %s: %w", ErrACLUnreadable, candidate, path, readErr)
		}
	}
	return "", nil, nil
}

// controllersOf returns every principal that can dismantle path's OWN protection -- take
// the ownership that gates chmod and chown, rewrite the access-control list, or remove an
// entry it does not own -- as opposed to one that can merely write inside it.
//
// Only NFSv4 can express any of those grants. Under POSIX.1e chmod and chown stay with the
// owner, whom the caller checks separately, removal is the kernel's sticky rule with nothing
// in the list able to override it, and no mode bit confers any of the three, so the answer
// is nothing rather than a guess.
func controllersOf(path string, stat *syscall.Stat_t) ([]principal, error) {
	name, blob, err := readACL(path)
	if err != nil {
		return nil, err
	}
	if name == xattrNFS4XDR {
		granted, err := parseNFS4Granted(blob, stat, nfs4ControlMask)
		if err != nil {
			return nil, fmt.Errorf("%w: %s holds %s: %w", ErrACLUnreadable, path, name, err)
		}
		return granted, nil
	}
	return nil, nil
}

// getxattrAll reads an access-control list attribute in ONE call, into a buffer sized to
// the largest list the parser for that dialect would accept.
//
// A single getxattr is atomic with respect to the attribute; a size probe followed by a
// read is not, and the principal who can use the gap between them is exactly the one this
// check exists to catch. A holder of WRITE_ACL on a path component can shrink or drop its
// own grant between the two calls, and all three outcomes read as good news: a second call
// answering ENODATA reaches the ABSENCE branch of [readACL], so a list granting EVERYONE@
// write yields no writers and no error; a shorter NFSv4 answer is parsed as a COMPLETE
// list, and an 8-byte header with a zero count is a valid empty one; and POSIX.1e carries
// no entry count at all, so any answer truncated to a multiple of the entry size is a
// valid SHORTER list. The check runs on every operation, so that window is available on
// demand rather than once.
//
// ERANGE therefore means "longer than any list this package would parse", which is a
// refusal rather than a reason to retry with a bigger buffer. A zero-length value is
// refused for the same reason: the kernel reports an absent attribute as ENODATA, so a
// present-but-empty one is a shape no parser here can explain. Neither is returned as
// ENODATA, so both reach [readACL]'s unreadable path instead of its absence path.
func getxattrAll(path, attr string) ([]byte, error) {
	buf := make([]byte, aclCeiling(attr))
	n, err := getxattrFn(path, attr, buf)
	switch {
	case errors.Is(err, syscall.ERANGE):
		return nil, fmt.Errorf("%s is longer than the %d bytes this parser would accept: %w", attr, len(buf), err)
	case err != nil:
		return nil, err
	case n <= 0:
		return nil, fmt.Errorf("%s is present but %d bytes long, which is not a list this parser can read", attr, n)
	case n > len(buf):
		return nil, fmt.Errorf("%s answered %d bytes into a %d byte buffer", attr, n, len(buf))
	}
	return buf[:n], nil
}

// aclCeiling returns the largest value the parser for attr would accept, which is the
// buffer size that makes one getxattr sufficient. Anything longer is over a limit that
// parser already refuses, so the ERANGE it produces is the same refusal arriving earlier.
func aclCeiling(attr string) int {
	if attr == xattrPOSIXACL {
		return posixACLHeaderSize + posixACLMaxEntries*posixACLEntrySize
	}
	return nfs4HeaderSize + nfs4MaxACEs*nfs4ACESize
}

// getxattrFn is syscall.Getxattr, replaced in tests: no ordinary test process can mount
// a filesystem that serves an NFSv4 ACL, and that dialect drives the branch this
// package most needs covered.
var getxattrFn = syscall.Getxattr

// parseACL dispatches on the attribute name.
//
// xattrNFS4ACL is deliberately absent: [readACL] refuses that dialect by name rather than
// handing it to a decoder whose layout does not fit it, so a blob in it never reaches here.
func parseACL(name string, blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	switch name {
	case xattrPOSIXACL:
		return parsePOSIXACL(blob, stat)
	case xattrNFS4XDR:
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
func parsePOSIXACL(blob []byte, stat *syscall.Stat_t) ([]principal, error) {
	entries, err := decodePOSIXACL(blob)
	if err != nil {
		return nil, err
	}
	// The mask has to be known before the maskable entries can be judged, and it may
	// appear after them in the list, which is why decoding and judging are two passes.
	mask, err := posixMask(entries)
	if err != nil {
		return nil, err
	}
	var out []principal
	for _, e := range entries {
		// OTHER is not subject to the mask, and it is the one tag whose grant would
		// otherwise be known only from the mode. Reading it from the LIST is what stops
		// this parser trusting the two to agree -- the assumption it exists to refuse.
		if e.tag == posixTagOther {
			if e.perm&posixPermWrite != 0 {
				out = append(out, principal{kind: principalEveryone})
			}
			continue
		}
		if e.perm&mask&posixPermWrite == 0 {
			continue
		}
		switch e.tag {
		case posixTagUser:
			out = append(out, principal{kind: principalUser, id: int(e.id)})
		case posixTagGroup:
			out = append(out, principal{kind: principalGroup, id: int(e.id)})
		case posixTagGroupObj:
			// The OWNING group, whose id the entry does not carry -- it is the object's
			// own gid. Naming it from the list is the last place this parser could have
			// read a grant off the mode instead, which is the assumption the rest of it
			// refuses to make. It IS subject to the mask, unlike OTHER, so it is judged
			// by the masked test above like any named entry.
			out = append(out, principal{kind: principalGroup, id: int(stat.Gid)})
		}
	}
	return out, nil
}

// posixMask returns the ceiling every named entry is capped by, or all-permissions when
// the list carries no mask at all.
//
// A valid access ACL carries at most ONE mask. Two of them cannot be composed without
// choosing which is the ceiling, and choosing the later one lets a second entry retire the
// first and hide every named writer beneath it. posix_acl_valid refuses a duplicate on
// setxattr, so the local kernel will not produce this; a filesystem or a remote server
// handing over the raw blob can, which is the case this refuses rather than resolves.
func posixMask(entries []posixEntry) (uint16, error) {
	mask := uint16(0xFFFF)
	seen := false
	for _, e := range entries {
		if e.tag != posixTagMask {
			continue
		}
		if seen {
			return 0, errors.New("the list carries more than one mask entry")
		}
		mask, seen = e.perm, true
	}
	return mask, nil
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
	if err := requirePOSIXTriple(out); err != nil {
		return nil, err
	}
	return out, nil
}

// requirePOSIXTriple refuses a list that does not carry USER_OBJ, GROUP_OBJ and OTHER
// exactly once each.
//
// It is load-bearing rather than pedantic, and it is what makes [writersOf] safe to take no
// mode floor for this dialect: the mode's group bits are this list's MASK rather than its
// GROUP_OBJ grant, so the owning group and everyone are named from the LIST or not at all.
// A blob missing either entry would then answer "nobody" for a principal the object may
// grant write to, which is the fail-open direction. posix_acl_valid demands the same three
// on setxattr, so the local kernel will not produce a list without them; a filesystem or a
// remote server handing over the raw blob can.
func requirePOSIXTriple(entries []posixEntry) error {
	for _, required := range []struct {
		name string
		tag  uint16
	}{
		{"user::", posixTagUserObj},
		{"group::", posixTagGroupObj},
		{"other::", posixTagOther},
	} {
		n := 0
		for _, e := range entries {
			if e.tag == required.tag {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("the list carries %d %s entries rather than exactly one", n, required.name)
		}
	}
	return nil
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
	return parseNFS4Granted(blob, stat, nfs4WriteMask)
}

// parseNFS4Granted is parseNFS4ACL over a caller-chosen set of access-mask bits, so the
// "who can write here" and "who can dismantle this" questions run one parser rather than
// two that can drift apart.
func parseNFS4Granted(blob []byte, stat *syscall.Stat_t, want uint32) ([]principal, error) {
	if len(blob) < nfs4HeaderSize {
		return nil, fmt.Errorf("%d bytes is shorter than the %d byte header", len(blob), nfs4HeaderSize)
	}
	count := binary.BigEndian.Uint32(blob[4:8])
	if count > nfs4MaxACEs {
		return nil, fmt.Errorf("%d entries is over the %d limit", count, nfs4MaxACEs)
	}
	body := blob[nfs4HeaderSize:]
	if need := int(count) * nfs4ACESize; len(body) != need {
		return nil, fmt.Errorf("%d entries need %d bytes of body, got %d", count, need, len(body))
	}

	var out []principal
	for i := range int(count) {
		raw := body[i*nfs4ACESize : (i+1)*nfs4ACESize]
		aceType := binary.BigEndian.Uint32(raw[0:4])
		flag := binary.BigEndian.Uint32(raw[4:8])
		special := binary.BigEndian.Uint32(raw[8:12])
		mask := binary.BigEndian.Uint32(raw[12:16])
		id := binary.BigEndian.Uint32(raw[16:20])

		// The four types RFC 7530 defines. ALLOW is the only one that grants, and the
		// other three are passed over: DENY can only ever subtract, and AUDIT and ALARM
		// ask the server to log or signal rather than to permit anything.
		//
		// An UNRECOGNISED type is refused instead, because "not ALLOW" and "cannot
		// grant" are not the same claim. A filesystem-extended or future type this
		// parser silently skipped would drop the writer it names, and a writer set with
		// a writer missing is a clean verdict no caller can refuse on -- the one
		// direction this check must never fail in.
		switch aceType {
		case nfs4TypeAllow:
		case nfs4TypeDeny, nfs4TypeAudit, nfs4TypeAlarm:
			continue
		default:
			return nil, fmt.Errorf("entry %d carries unknown type %d", i, aceType)
		}
		if flag&nfs4FlagInheritOnly != 0 || mask&want == 0 {
			continue
		}
		switch {
		case special == 0:
			kind := principalUser
			if flag&nfs4FlagIdentifierGroup != 0 {
				kind = principalGroup
			}
			out = append(out, principal{kind: kind, id: int(id)})
		case special != nfs4WhoIsSpecial:
			// Not a discriminator this parser understands, so the id cannot be read as
			// either a uid or a special principal. Guessing which costs a write grant
			// in the silent direction: an ALLOW entry naming uid 1 under an unknown
			// discriminator would read as OWNER@ and be dropped from the writer set,
			// and a set missing a writer is a clean verdict nobody can refuse on.
			return nil, fmt.Errorf("entry %d carries unknown whoIsSpecial %d", i, special)
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
		// Group 0 is trusted, and NOT for the reason it is tempting to give: membership of
		// the root group is not root's privilege. A uid 1000 process holding gid 0 gets
		// write on a root:root 0770 tree and nothing else root can do, so on a host where
		// group root has members this check does not cover them. That is a stated limit,
		// not an oversight.
		//
		// It stays because the asymmetry runs the other way. The walk judges EVERY
		// ancestor, so refusing gid 0 would refuse a single root:root 0775 component --
		// what `install -d -m 775` produces as root, and what /usr/local is on Debian --
		// and turn an ordinary tree into a total install outage. Being wrong by trusting
		// costs a clean verdict where an admin who already had root chose to add a member;
		// being wrong by refusing costs every install on a normal host.
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
