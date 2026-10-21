package adapter

import (
	"path"
	"strings"
)

// Signature declares a location an adapter owns within an fs.FS, expressed
// as data rather than glob syntax.
type Signature struct {
	// Dir anchors the signature.
	Dir string
	// File is the exact filename within Dir.
	File string
	// Recursive selects Dir and every descendant path, not a single file.
	// Dir "." anchors the whole tree; an unset Dir selects nothing.
	Recursive bool
	// AnyDepth selects a depth-agnostic match: p matches when its trailing
	// segments are exactly Dir/File, at any depth, so one literal owns
	// ".claude-plugin/plugin.json" and its nested copies alike.
	AnyDepth bool
}

// Matches reports whether p, a plain fs.FS path as fs.WalkDir yields it, is
// owned by any of sigs, treating p as a regular file.
func Matches(p string, sigs []Signature) bool {
	return MatchesEntry(p, false, sigs)
}

// MatchesEntry reports whether the walked entry at p, a directory when isDir
// is true, is owned by any of sigs.
//
// Only an AnyDepth signature matches a directory entry, which
// TestMatchesEntryDirectoryTypedMarker pins: its marker is security-relevant
// by presence alone, so an attacker must not hide it behind an empty
// directory that a directory-blind walk would never enter. Matching
// directories in the other modes would only manufacture a spurious Source
// per recursive signature.
func MatchesEntry(p string, isDir bool, sigs []Signature) bool {
	for _, s := range sigs {
		if isDir && !s.AnyDepth {
			continue
		}
		if matchOne(p, s) {
			return true
		}
	}
	return false
}

// matchOne reports whether p is owned by a single Signature s. The Recursive
// and AnyDepth branches demand a path-segment boundary rather than a string
// prefix/suffix, which is what rejects ".claude-evil" against ".claude".
func matchOne(p string, s Signature) bool {
	if s.AnyDepth {
		suffix := path.Join(s.Dir, s.File)
		return p == suffix || strings.HasSuffix(p, "/"+suffix)
	}
	if s.Recursive {
		// fs.WalkDir yields the root as "." and descendants unrooted, so a
		// root anchor leaves no prefix for a segment-boundary test to hold
		// onto. Only the explicit "." opts in, keeping a zero value inert.
		if s.Dir == "." {
			return true
		}
		return p == s.Dir || strings.HasPrefix(p, s.Dir+"/")
	}
	return p == path.Join(s.Dir, s.File)
}
