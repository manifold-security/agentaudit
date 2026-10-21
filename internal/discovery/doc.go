// Package discovery is an internal, agent-agnostic config-source walker.
//
// Its non-test code consumes fs.FS ONLY, never os — pinned by
// cmd/agentaudit's TestOSIsolation_EngineAndReporterPackages — so a real
// project directory (os.DirFS) and an in-memory fixture (fstest.MapFS) run
// through one engine, with fs.FS the only injection point.
//
// Discover is LOCATION-only: it finds paths, it does not parse them. Building
// ir.Entity values is the adapter's Parse, and findings are the engine's.
//
// Resolving user-scope config such as `~/.claude.json` is a non-goal: a
// project-rooted fs.FS cannot express a $HOME-rooted path.
package discovery
