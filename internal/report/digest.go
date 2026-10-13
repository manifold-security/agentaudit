package report

import (
	"crypto/sha256"
	"encoding/hex"
)

// Digest reduces a Finding's raw ID() into a fixed-width lowercase hex
// string, since the raw id's 0x1f-joined parts do not survive intact.
func Digest(rawID string) string {
	sum := sha256.Sum256([]byte(rawID))
	return hex.EncodeToString(sum[:16])
}
