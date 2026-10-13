// Package hostroot locates the project root a host-declared path set is
// relative to. A directory picker puts the chosen folder's own name ahead of
// every path it hands the host, and root-anchored adapter signatures match
// only relative to the project root. The root is chosen from that folder's
// name alone, because the files beneath it are authored by the repository
// under scan; they can only make Rebase refuse the set.
package hostroot

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
)

var (
	errAmbiguousRoot   = errors.New("every declared path sits inside a folder named like an agent config folder that holds agent config of its own, so whether that folder or its parent is the project root is ambiguous")
	errMarkerFolder    = errors.New("every declared path sits inside a folder named like a plugin marker that holds more than the marker's manifest, so whether that folder or its parent is the project root is ambiguous")
	errConfigBelowRoot = errors.New("the declared paths hold agent config only below the project root, where a scan does not read it")
)

// Rebase returns files keyed relative to the project root they were declared
// under, and never drops a file.
func Rebase(files map[string][]byte, adapters []adapter.Adapter) (map[string][]byte, error) {
	names := slices.Sorted(maps.Keys(files))
	for _, name := range names {
		if !fs.ValidPath(name) || name == "." {
			return nil, fmt.Errorf("hostroot: refusing %q: not an unrooted slash-separated path", name)
		}
	}
	s := newSignatures(adapters)
	root, err := s.root(names)
	if err != nil {
		return nil, fmt.Errorf("hostroot: %w", err)
	}
	if dir, ok := s.configBelow(names, root); ok {
		return nil, fmt.Errorf("hostroot: %w: %q", errConfigBelowRoot, dir)
	}
	if root == "" {
		return files, nil
	}
	rebased := make(map[string][]byte, len(files))
	for name, data := range files {
		rebased[strings.TrimPrefix(name, root+"/")] = data
	}
	return rebased, nil
}

type signatures struct {
	anchored      []adapter.Signature
	anyDepth      []adapter.Signature
	configFolders map[string]bool
	markers       map[string]bool
	manifests     map[string]bool
}

func newSignatures(adapters []adapter.Adapter) signatures {
	s := signatures{
		configFolders: map[string]bool{},
		markers:       map[string]bool{},
		manifests:     map[string]bool{},
	}
	for _, a := range adapters {
		for _, sig := range a.Signatures() {
			if sig.AnyDepth {
				s.anyDepth = append(s.anyDepth, sig)
				s.markers[sig.Dir] = true
				s.manifests[path.Join(sig.Dir, sig.File)] = true
				continue
			}
			s.anchored = append(s.anchored, sig)
			if first, _, _ := strings.Cut(sig.Dir, "/"); first != "" && first != "." {
				s.configFolders[first] = true
			}
		}
	}
	return s
}

func (s signatures) root(names []string) (string, error) {
	folder := sharedFolder(names)
	switch {
	case s.configFolders[folder]:
		if s.configAt(names, folder) {
			return "", fmt.Errorf("%w: %q", errAmbiguousRoot, folder)
		}
		return "", nil
	case s.markers[folder]:
		for _, name := range names {
			if !s.manifests[name] {
				return "", fmt.Errorf("%w: %q", errMarkerFolder, folder)
			}
		}
		return "", nil
	}
	return folder, nil
}

func sharedFolder(names []string) string {
	folder := ""
	for i, name := range names {
		first, _, nested := strings.Cut(name, "/")
		if !nested || (i > 0 && first != folder) {
			return ""
		}
		folder = first
	}
	return folder
}

func (s signatures) configAt(names []string, dir string) bool {
	for _, name := range names {
		if adapter.Matches(relative(name, dir), s.anchored) {
			return true
		}
	}
	return false
}

// configBelow passes over a plugin manifest in the marker folder that holds
// it, where its own name matches a bare root-level plugin.json signature.
func (s signatures) configBelow(names []string, root string) (string, bool) {
	if s.configAt(names, root) {
		return "", false
	}
	for _, name := range names {
		manifest := adapter.Matches(name, s.anyDepth)
		for dir := path.Dir(name); dir != "." && dir != root; dir = path.Dir(dir) {
			if manifest && dir == path.Dir(name) {
				continue
			}
			if adapter.Matches(relative(name, dir), s.anchored) {
				return dir, true
			}
		}
	}
	return "", false
}

func relative(name, dir string) string {
	if dir == "" {
		return name
	}
	return strings.TrimPrefix(name, dir+"/")
}
