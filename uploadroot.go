package agentaudit

import (
	"github.com/manifold-security/agentaudit/internal/hostroot"
	"github.com/manifold-security/agentaudit/internal/registry"
)

// UploadRoot returns the folder to strip from an uploaded archive's paths, or
// "" when there is none. paths are the archive's non-directory entry names,
// each an fs.ValidPath.
func UploadRoot(paths []string) (root string, err error) {
	return hostroot.Root(paths, registry.Adapters())
}
