// Package remote fetches a public GitHub repository's agent configuration
// into memory for agentaudit to scan.
//
// Fetch speaks git's smart HTTP protocol to github.com with no credentials:
// one ref advertisement, one depth-1 request for the commit's trees without
// their blobs, then requests naming only the blobs a Select round's scan
// read. Every request after the advertisement names objects of the commit
// Fetch resolved, so the tree is pinned to that commit.
//
// Limits bounds a fetch. Each pack is buffered and checked against it before
// any of it is stored, so no object over a limit is held inflated in memory.
//
// Its own non-test code imports net/http and nothing else under os, net,
// syscall or path/filepath, which cmd/agentaudit's
// TestOSIsolation_RemoteImportsGoGitAndNoOtherForbiddenPackageThanNetHTTP
// pins. go-git, which it calls, links a disk filesystem, and nothing here
// proves that link unused.
package remote
