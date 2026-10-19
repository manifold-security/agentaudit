package remote

import "fmt"

// Limits bounds what one Fetch downloads and holds. Sizes are in bytes.
type Limits struct {
	// Rounds bounds the Select rounds; a path still unasked after the last
	// one is withheld.
	Rounds int
	// TreeEntries bounds the entries listed below the tree's root, the
	// /tree/ path when there is one, directories included.
	TreeEntries int
	// PathBytes bounds the summed byte length of the listed entries' paths,
	// directories included.
	PathBytes int64
	// Files bounds the blobs fetched.
	Files int
	// RefsBytes bounds the ref advertisement, which grows with a
	// repository's refs.
	RefsBytes int64
	// PackBytes bounds each pack response.
	PackBytes int64
	// FileBytes bounds each object. Over it, an asked-for blob sent whole is
	// withheld if the total stays within TotalBytes; anything else is fatal.
	FileBytes int64
	// TotalBytes bounds the inflated size of the objects stored, together
	// with those of the pack being checked, a blob it withholds included.
	TotalBytes int64
}

// DefaultLimits returns the limits a caller starts from.
func DefaultLimits() Limits {
	return Limits{
		Rounds:      8,
		TreeEntries: 200_000,
		PathBytes:   32 << 20,
		Files:       2_000,
		RefsBytes:   32 << 20,
		PackBytes:   16 << 20,
		FileBytes:   5 << 20,
		TotalBytes:  64 << 20,
	}
}

func (l Limits) validate() error {
	for name, n := range map[string]int64{
		"Rounds":      int64(l.Rounds),
		"TreeEntries": int64(l.TreeEntries),
		"PathBytes":   l.PathBytes,
		"Files":       int64(l.Files),
		"RefsBytes":   l.RefsBytes,
		"PackBytes":   l.PackBytes,
		"FileBytes":   l.FileBytes,
		"TotalBytes":  l.TotalBytes,
	} {
		if n <= 0 {
			return fmt.Errorf("remote: Limits.%s is %d, want it positive", name, n)
		}
	}
	return nil
}
