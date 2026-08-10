package pinstall

import (
	"encoding/base64"
	"encoding/binary"
	"slices"
	"syscall"
	"testing"
)

// Real access-control lists, read from an OpenZFS nfsv4 dataset and captured verbatim
// with their stat data. They are the fixtures that pin the wire format, because that
// format is not something to infer from a specification and hope: every field below was
// cross-checked against nfs4xdr_getfacl's rendering of the same object, bit for bit.
//
// The first sample is the lossy case this whole check exists for: mode 0770 shows the
// owning group write, and says nothing at all about the named user who also has it. A
// mode-only reading of that directory misses uid 3000 entirely.
//
// The other two are the correction to my own reading of the same tree, and they are here
// so nobody repeats it. Their wide group@ entries are INHERIT_ONLY, so they do not apply
// to the directory itself; they are copied onto things created inside it, which is why a
// 0700 mkdir there stores 0770 while the directory is 0750. Parsing the list is what tells
// those two situations apart, and eyeballing nfs4xdr_getfacl output is what does not.
var nfs4Samples = map[string]struct {
	b64  string
	uid  uint32
	gid  uint32
	mode uint32
	want []principal
}{
	"dataset root, owned by apps, mode 0770 with a named admin and a group grant": {
		b64:  "AAIAAAAAAAQAAAAAAAAAAwAAAAAAHwH/AAALuAAAAAAAAAADAAAAAQAeAf8AAAABAAAAAAAAAEMAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAEgCIAAAAAw==",
		uid:  568,
		gid:  568,
		mode: 0o770,
		want: []principal{
			{kind: principalUser, id: 3000}, // the named admin, WRITE_DATA and more
			{kind: principalGroup, id: 568}, // group@, resolved to the object's gid
		},
	},
	"root-owned tools directory, mode 0750": {
		b64:  "AAIAAAAAAAYAAAAAAAAAgwAAAAAAHwH/AAALuAAAAAAAAACLAAAAAQAeAf8AAAABAAAAAAAAAMsAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAHgH/AAAAAQAAAAAAAABAAAAAAQASAKkAAAACAAAAAAAAAAAAAAABABIAiAAAAAM=",
		uid:  0,
		gid:  0,
		mode: 0o750,
		// Only the admin. The wide group@ entry on this directory is INHERIT_ONLY
		// (rendered "fdi" by nfs4xdr_getfacl), so it does not apply to the directory
		// itself — it exists to be copied onto things created inside it, which is
		// exactly why a 0700 mkdir there stores 0770 while the directory itself is
		// 0750. The entry that does apply grants the group r-x.
		want: []principal{{kind: principalUser, id: 3000}},
	},
	"root:apps config directory, mode 0750": {
		b64:  "AAIAAAAAAAYAAAAAAAAAgwAAAAAAHwH/AAALuAAAAAAAAACLAAAAAQAeAf8AAAABAAAAAAAAAMsAAAABABIA7wAAAAIAAAAAAAAAAAAAAAEAHgH/AAAAAQAAAAAAAABAAAAAAQASAKkAAAACAAAAAAAAAAAAAAABABIAiAAAAAM=",
		uid:  0,
		gid:  568,
		mode: 0o750,
		// Same shape: the group@ entry granting write is inherit-only, so the
		// directory on the path is writable only by the admin. This is the sample that
		// corrected my own reading of the tree — the mode understates for the
		// directory's CHILDREN, not for the directory.
		want: []principal{{kind: principalUser, id: 3000}},
	},
}

// TestParseNFS4ACLAgainstRealSamples pins the NFSv4 parser on lists this fleet actually
// carries. A hand-built fixture would only prove the parser agrees with my reading of the
// format; these prove it agrees with the filesystem.
func TestParseNFS4ACLAgainstRealSamples(t *testing.T) {
	for name, tc := range nfs4Samples {
		t.Run(name, func(t *testing.T) {
			blob, err := base64.StdEncoding.DecodeString(tc.b64)
			if err != nil {
				t.Fatalf("decoding the fixture: %v", err)
			}
			got, err := parseNFS4ACL(blob, &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid})
			if err != nil {
				t.Fatalf("parseNFS4ACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseNFS4ACLRefusesMalformedInput pins the parser's own boundary. It reads
// untrusted bytes off a filesystem, so every shape that is not a well-formed list has to
// be an error rather than a short read that silently reports fewer writers than there
// are — under-reporting writers is how this check would wave through the exact tree it
// exists to refuse.
func TestParseNFS4ACLRefusesMalformedInput(t *testing.T) {
	valid, err := base64.StdEncoding.DecodeString(nfs4Samples["dataset root, owned by apps, mode 0770 with a named admin and a group grant"].b64)
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	tests := map[string][]byte{
		"empty":                    {},
		"header only":              valid[:8],
		"truncated header":         valid[:4],
		"one byte short of an ace": valid[:len(valid)-1],
		"one byte long":            append(slices.Clone(valid), 0),
		"count larger than body":   append(slices.Clone(valid[:4]), 0xFF, 0xFF, 0xFF, 0xFF),
	}
	for name, blob := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseNFS4ACL(blob, &syscall.Stat_t{}); err == nil {
				t.Error("parseNFS4ACL accepted a malformed list")
			}
		})
	}
}

// TestParseNFS4ACLSkipsWhatCannotGrantWrite pins the three reasons an entry is passed
// over, each of which would otherwise produce a spurious writer and a refusal nobody can
// act on.
func TestParseNFS4ACLSkipsWhatCannotGrantWrite(t *testing.T) {
	tests := map[string]struct {
		aceType, flag, special, mask, id uint32
		want                             []principal
	}{
		"a deny entry": {
			aceType: 1, special: 0, mask: nfs4WriteData, id: 4242,
		},
		"an inherit-only entry": {
			flag: nfs4FlagInheritOnly, special: 0, mask: nfs4WriteData, id: 4242,
		},
		"an allow entry with no write bit": {
			special: 0, mask: 0x00120088, id: 4242,
		},
		"an allow entry that only writes attributes": {
			special: 0, mask: 0x00000110, id: 4242,
		},
		"a named user with write": {
			special: 0, mask: nfs4WriteData, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"a named group with write": {
			flag: nfs4FlagIdentifierGroup, special: 0, mask: nfs4AppendData, id: 77,
			want: []principal{{kind: principalGroup, id: 77}},
		},
		"a principal who can rewrite the acl": {
			special: 0, mask: nfs4WriteACL, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"a principal who can take ownership": {
			special: 0, mask: nfs4WriteOwner, id: 4242,
			want: []principal{{kind: principalUser, id: 4242}},
		},
		"everyone with write": {
			special: 1, mask: nfs4WriteData, id: nfs4WhoEveryone,
			want: []principal{{kind: principalEveryone}},
		},
		"the owner with write": {
			special: 1, mask: nfs4WriteData, id: nfs4WhoOwner,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(tc.aceType, tc.flag, tc.special, tc.mask, tc.id)
			got, err := parseNFS4ACL(blob, &syscall.Stat_t{Gid: 9})
			if err != nil {
				t.Fatalf("parseNFS4ACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParsePOSIXACLAppliesTheMask pins the one thing that makes POSIX.1e different: the
// mask is the ceiling on every named entry and on the owning group, so an entry granting
// write under a mask that withholds it grants nothing. Getting this backwards would
// refuse every ordinary Linux volume that happens to carry an ACL.
func TestParsePOSIXACLAppliesTheMask(t *testing.T) {
	const rwx, rx = 7, 5
	tests := map[string]struct {
		entries []posixACLEntry
		want    []principal
	}{
		"a named user with write, unmasked": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
			want: []principal{{kind: principalUser, id: 1234}},
		},
		"the same user, capped by the mask": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
		},
		"a named group with write, unmasked": {
			entries: []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroup, perm: rwx, id: 77},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
			want: []principal{{kind: principalGroup, id: 77}},
		},
		"a mask appearing before the entries it caps": {
			entries: []posixACLEntry{
				{tag: posixTagMask, perm: rx, id: aclUndefinedID},
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagUser, perm: rwx, id: 1234},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: rx, id: aclUndefinedID},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parsePOSIXACL(encodePOSIXACL(tc.entries))
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			if !samePrincipals(got, tc.want) {
				t.Errorf("writers = %v, want %v", got, tc.want)
			}
		})
	}
}

// samePrincipals compares two writer sets without caring about order.
func samePrincipals(got, want []principal) bool {
	if len(got) != len(want) {
		return false
	}
	remaining := slices.Clone(want)
	for _, g := range got {
		i := slices.Index(remaining, g)
		if i < 0 {
			return false
		}
		remaining = slices.Delete(remaining, i, i+1)
	}
	return true
}

// ACL builders shared by the tests. The on-disk formats are stable kernel and protocol
// ABI, so encoding them by hand keeps the suite free of a setfacl binary that many
// minimal images (including the container this was written in) do not ship, and lets a
// test express a list no tool would let it write.
const aclUndefinedID uint32 = 0xFFFFFFFF

// posixACLEntry is one entry in the POSIX.1e xattr encoding.
type posixACLEntry struct {
	id   uint32
	tag  uint16
	perm uint16
}

// encodePOSIXACL renders entries in the system.posix_acl_access layout.
func encodePOSIXACL(entries []posixACLEntry) []byte {
	blob := binary.LittleEndian.AppendUint32(nil, posixACLVersion)
	for _, e := range entries {
		blob = binary.LittleEndian.AppendUint16(blob, e.tag)
		blob = binary.LittleEndian.AppendUint16(blob, e.perm)
		blob = binary.LittleEndian.AppendUint32(blob, e.id)
	}
	return blob
}

// buildNFS4ACL renders a one-entry NFSv4 list in the system.nfs4_acl_xdr layout.
func buildNFS4ACL(aceType, flag, special, mask, id uint32) []byte {
	blob := binary.BigEndian.AppendUint32(nil, 0)
	blob = binary.BigEndian.AppendUint32(blob, 1)
	for _, field := range []uint32{aceType, flag, special, mask, id} {
		blob = binary.BigEndian.AppendUint32(blob, field)
	}
	return blob
}

// setPOSIXACL writes entries as path's POSIX access ACL, for the tests that want a real
// one the kernel enforces rather than a parsed fixture.
func setPOSIXACL(path string, entries []posixACLEntry) error {
	return syscall.Setxattr(path, xattrPOSIXACL, encodePOSIXACL(entries), 0)
}

// posixACLNamedUserUnderMask grants a named user rwx while the mask allows only r-x, so
// the user ends up without write and the directory's mode stays 0755.
var posixACLNamedUserUnderMask = []posixACLEntry{
	{tag: posixTagUserObj, perm: 7, id: aclUndefinedID},
	{tag: posixTagUser, perm: 7, id: 1234},
	{tag: posixTagGroupObj, perm: 5, id: aclUndefinedID},
	{tag: posixTagMask, perm: 5, id: aclUndefinedID},
	{tag: posixTagOther, perm: 5, id: aclUndefinedID},
}

// TestParseNFS4ACLRefusesAnUnknownDiscriminator pins the direction this parser must never
// fail in. whoIsSpecial says whether an ACE's id is a uid/gid or a special-principal
// number, and reading "not zero" as "special" makes the two answers trade places: an
// ALLOW entry naming uid 1 under an unrecognised discriminator reads as OWNER@, which the
// caller checks separately and this parser therefore DROPS. A writer set missing a writer
// is a clean custody verdict, and no call site can refuse on a verdict that carries no
// error -- so a silent drop is strictly worse than any over-report.
//
// The values matter because of which xattr this is: system.nfs4_acl carries the NFS
// SERVER's list as relayed by the client, so the discriminator is chosen by whoever
// administers the export rather than validated by the local kernel's own setters.
func TestParseNFS4ACLRefusesAnUnknownDiscriminator(t *testing.T) {
	const grantedID = 1 // equal to nfs4WhoOwner, which is what makes the drop silent
	stat := &syscall.Stat_t{Gid: 9}

	tests := map[string]struct {
		special uint32
		wantErr bool
		// wantOwner marks the one case where an empty writer set is the RIGHT answer:
		// the entry really does name OWNER@, whose ownership the caller checks itself.
		wantOwner bool
	}{
		"named, the discriminator this parser understands": {special: 0},
		"special, naming OWNER@ which the caller checks":   {special: nfs4WhoIsSpecial, wantOwner: true},
		"two, which used to read a uid as OWNER@":          {special: 2, wantErr: true},
		"three":                                  {special: 3, wantErr: true},
		"a flag bit, not a discriminator at all": {special: 0x40, wantErr: true},
		"every bit set":                          {special: 0xFFFFFFFF, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			blob := buildNFS4ACL(nfs4TypeAllow, 0, tc.special, nfs4WriteData, grantedID)

			writers, err := parseNFS4ACL(blob, stat)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) = %v, nil; want an error rather than a writer set that may be missing the granted identity",
					tc.special, writers)
			case !tc.wantErr && err != nil:
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) = %v on a discriminator it understands", tc.special, err)
			}
			// The fail-open shape itself: an empty set with no error, for a list that
			// grants write to somebody. Only OWNER@ may answer that way, and only
			// because ownership is checked separately by the caller.
			if err == nil && !tc.wantOwner && len(writers) == 0 {
				t.Errorf("parseNFS4ACL(whoIsSpecial=%d) reported no writers and no error for an ALLOW entry granting write to id %d",
					tc.special, grantedID)
			}
		})
	}
}

// TestParsePOSIXACLRefusesASecondMask pins that a duplicate mask is refused rather than
// resolved by taking the last one. The mask is a CEILING on every named entry, so a
// second one silently retires the first and hides every named writer under it.
// posix_acl_valid rejects this on setxattr, so the local kernel cannot produce it; a
// filesystem or a remote server handing over the raw blob can.
func TestParsePOSIXACLRefusesASecondMask(t *testing.T) {
	const rwx, rx = 7, 5

	hidden := []posixACLEntry{
		{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
		{tag: posixTagMask, perm: rwx, id: aclUndefinedID},
		{tag: posixTagUser, perm: rwx, id: 1234},
		{tag: posixTagMask, perm: rx, id: aclUndefinedID},
		{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
		{tag: posixTagOther, perm: rx, id: aclUndefinedID},
	}

	writers, err := parsePOSIXACL(encodePOSIXACL(hidden))
	if err == nil {
		t.Errorf("parsePOSIXACL(two masks) = %v, nil; want a refusal rather than a set the second mask emptied", writers)
	}
}

// TestParsePOSIXACLReadsOtherFromTheList pins the last place this parser could have
// relied on the mode instead of the list. An OTHER entry granting write names everyone,
// and it must do so from the ACL itself: posix_acl_update_mode keeps the two in step on
// Linux, but "these two always match" is the assumption the whole check exists to refuse,
// and the mode is the half an attacker-facing filesystem controls independently.
func TestParsePOSIXACLReadsOtherFromTheList(t *testing.T) {
	const rwx, rx = 7, 5

	tests := map[string]struct {
		other uint16
		want  bool
	}{
		"other may write":      {other: rwx, want: true},
		"other may not write":  {other: rx, want: false},
		"other may do nothing": {other: 0, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries := []posixACLEntry{
				{tag: posixTagUserObj, perm: rwx, id: aclUndefinedID},
				{tag: posixTagGroupObj, perm: rx, id: aclUndefinedID},
				{tag: posixTagOther, perm: tc.other, id: aclUndefinedID},
			}

			writers, err := parsePOSIXACL(encodePOSIXACL(entries))
			if err != nil {
				t.Fatalf("parsePOSIXACL: %v", err)
			}
			got := slices.Contains(writers, principal{kind: principalEveryone})
			if got != tc.want {
				t.Errorf("parsePOSIXACL(other=%#o) named everyone = %v, want %v (writers=%v)",
					tc.other, got, tc.want, writers)
			}
		})
	}
}
