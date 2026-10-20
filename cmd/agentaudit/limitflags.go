package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type limitFlag struct {
	name  string
	err   error
	fired bool
}

func limitHint(flags []limitFlag) string {
	var names []string
	for _, l := range flags {
		if l.fired {
			names = append(names, l.name)
		}
	}
	switch len(names) {
	case 0:
		return ""
	case 1:
		return "hint: raise " + names[0] + " to scan the files it refused; 0 turns it off"
	}
	last := len(names) - 1
	return "hint: raise " + strings.Join(names[:last], ", ") + " and " + names[last] + " to scan the files they refused; 0 turns each off"
}

type byteCount string

func (b *byteCount) String() string { return string(*b) }

func (b *byteCount) Set(s string) error {
	*b = byteCount(s)
	return nil
}

func (*byteCount) Type() string { return "bytes" }

var byteUnits = []struct {
	suffix string
	size   int64
}{
	{"GiB", 1 << 30},
	{"MiB", 1 << 20},
	{"KiB", 1 << 10},
}

func parseBytes(s string) (int64, bool) {
	digits, size := s, int64(1)
	for _, u := range byteUnits {
		if len(s) >= len(u.suffix) && strings.EqualFold(s[len(s)-len(u.suffix):], u.suffix) {
			digits, size = s[:len(s)-len(u.suffix)], u.size
			break
		}
	}
	if strings.Trim(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n > math.MaxInt64/size {
		return 0, false
	}
	return n * size, true
}

func formatBytes(n int64) string {
	for _, u := range byteUnits {
		if n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

func byteLimit(flag string, value byteCount) (int64, error) {
	n, ok := parseBytes(string(value))
	if !ok {
		return 0, fmt.Errorf("agentaudit: %q is not a valid %s value (want a whole number of bytes, optionally followed by KiB, MiB or GiB; 0 turns the limit off)", string(value), flag)
	}
	return n, nil
}
