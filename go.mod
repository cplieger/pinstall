module github.com/cplieger/pinstall/v2

go 1.26.5

require github.com/cplieger/pathinside v1.0.0

// v2.0.1 is the SAME TREE as v2.1.0 — both tag ef37c2f. It is the patch number the
// changelog tool computed for a span of `sec:` commits, published as a lightweight tag;
// the release was then re-cut by hand as the annotated minor v2.1.0, because each of
// those commits is a refusal a volume that installed cleanly under v2.0.0 may now
// receive, and a restriction consumers must be told about is not a patch. The stray
// already reached the module proxy, where versions are immutable, so deleting the tag
// would retract nothing and only leave the number unexplainable. This is the Go-native
// way to say "do not pin this one".
retract v2.0.1 // Same tree as v2.1.0, published accidentally as a patch. Use v2.1.0 or later.
