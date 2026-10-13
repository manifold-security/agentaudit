// Package adapter defines the public port implemented by agent adapters.
//
// Its non-test files import internal/ir and nothing else from this module,
// which TestPackagePurity pins; ir and finding bar io/fs from theirs, so
// fs.FS enters the domain here.
package adapter
