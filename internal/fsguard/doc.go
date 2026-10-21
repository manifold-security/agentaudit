// Package fsguard classifies an fs.FS entry by its own type bits before
// anything opens it: a FIFO planted at a declared config path blocks its
// opener until a writer appears, stalling the whole scan.
package fsguard
