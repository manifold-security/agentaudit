package report

import (
	"iter"
	"regexp"
	"strings"
)

const mask = "***"

const (
	shellBytes    = ";&|<>()${}`\\'\""
	wordEnds      = " \t\n"
	literalBytes  = shellBytes + wordEnds
	prefixedPunct = "_-"
	userNamePunct = "._~%+@-"
	segmentBreaks = ";|&()`\n\r"
	urlEnds       = " \t\r\n\"'`<>|(){}\\"
	authorityEnds = urlEnds + "/?#"
)

const (
	minPrefixedTail = 16
	accessKeyIDTail = 16
)

const hostWord = "auth"

var credentialWords = []string{"token", "secret", "password", "passwd", "pwd", "key", "auth", "credential", "credentials"}

var credentialName = "(?:" + strings.Join(credentialWords, "|") + ")"

const urlScheme = `(?i)\b[a-z][a-z0-9+.-]*://`

var (
	credentialFlag = regexp.MustCompile(`(?i)^--[a-z0-9_-]*` + credentialName + `$`)
	credentialVar  = regexp.MustCompile(`(?i)` + credentialName + `$`)
	schemes        = regexp.MustCompile(urlScheme)
	tokenPrefixes  = regexp.MustCompile(`\b(?:sk-ant-|gh[oprsu]_|github_pat_|glpat-|xox[abopsr]-)`)
	accessKeyIDs   = regexp.MustCompile(`\b(?:AKIA|ASIA)`)
)

type span struct{ from, to int }

var redactions = []struct {
	matches func(s string) iter.Seq[span]
	spans   func(dst []span, s string, end int) []span
}{
	{matchesOf(urlScheme, func(s string) bool { return strings.Contains(s, "://") }), userinfoSpans},
	{namedValueMatches, namedValueSpans},
	{matchesOf(`(?i)\b(?:proxy-)?authorization["']?:[ \t]*`, func(s string) bool { return containsFold(s, "authorization") }), authorizationSpans},
	{matchesOf(`(?im)(?:^|[ \t])--[a-z0-9_-]*`+credentialName+`[ \t]+`, func(s string) bool { return strings.Contains(s, "--") }), flagValueSpans},
	{standaloneMatches(tokenPrefixes, func(s string) bool { return strings.ContainsAny(s, "_-") }), after(prefixedSpan)},
}

var accessKeyIDMatches = standaloneMatches(accessKeyIDs, func(s string) bool { return strings.Contains(s, "AKIA") || strings.Contains(s, "ASIA") })

// Redact returns s with each credential it recognises replaced by ***,
// leaving the text around it visible. The shell syntax bytes inside a
// masked value, which TestRedact_KeepsShellBytesVisible lists, stay
// visible: the scanned config's author is the party a report warns
// about, and those bytes show where a command is chained to a value
// named like a credential.
func Redact(s string) string {
	for _, r := range redactions {
		s = maskAfter(s, r.matches(s), r.spans)
	}
	if containsFold(s, "curl") {
		s = maskCurlUsers(s)
	}
	return maskAfter(s, accessKeyIDMatches(s), after(accessKeyIDSpan))
}

func redactArgs(command string, args []string) []string {
	if len(args) == 0 {
		return args
	}
	underCurl := isCurl(firstWord(command))
	out := make([]string, len(args))
	for i, a := range args {
		underCurl = underCurl || isCurl(a)
		if i > 0 {
			switch prev := args[i-1]; {
			case credentialFlag.MatchString(prev):
				a = applySpans(a, elementSpans(nil, a))
			case underCurl && isUserFlag(prev):
				a = applySpans(a, userPassSpans(nil, a, 0))
			}
		}
		if at := attachedUserValue(a); underCurl && at > 0 {
			a = applySpans(a, userPassSpans(nil, a, at))
		}
		out[i] = Redact(a)
	}
	return out
}

func maskAfter(s string, matches iter.Seq[span], spans func([]span, string, int) []span) string {
	var b strings.Builder
	var found []span
	last := 0
	for m := range matches {
		if m.from < last {
			continue
		}
		found = spans(found[:0], s, m.to)
		for _, sp := range found {
			b.WriteString(s[last:sp.from])
			b.WriteString(mask)
			last = sp.to
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func matchesOf(pattern string, mayMatch func(string) bool) func(string) iter.Seq[span] {
	re := regexp.MustCompile(pattern)
	return func(s string) iter.Seq[span] {
		return func(yield func(span) bool) {
			if !mayMatch(s) {
				return
			}
			for _, m := range re.FindAllStringIndex(s, -1) {
				if !yield(span{m[0], m[1]}) {
					return
				}
			}
		}
	}
}

func namedValueMatches(s string) iter.Seq[span] {
	return func(yield func(span) bool) {
		for i := 0; ; {
			d := strings.IndexAny(s[i:], "=:")
			if d < 0 {
				return
			}
			d += i
			q := quoteLen(s[max(d-1, 0):d])
			if w := credentialWordBefore(s[:d-q]); w > 0 {
				end := d + 1
				if s[d] == ':' {
					end += blankLen(s[end:])
				}
				if !yield(span{d - q - w, end}) {
					return
				}
			}
			i = d + 1
		}
	}
}

func standaloneMatches(prefix *regexp.Regexp, mayMatch func(string) bool) func(string) iter.Seq[span] {
	return func(s string) iter.Seq[span] {
		return func(yield func(span) bool) {
			if !mayMatch(s) {
				return
			}
			urls := urlParts(s)
			for _, m := range prefix.FindAllStringIndex(s, -1) {
				for len(urls) > 0 && urls[0].url.to <= m[0] {
					urls = urls[1:]
				}
				inURL := len(urls) > 0 && urls[0].url.from <= m[0]
				switch {
				case inURL && urls[0].host.from <= m[0] && m[0] < urls[0].host.to:
					continue
				case !inURL && m[0] > 0 && (s[m[0]-1] == '/' || s[m[0]-1] == '\\'):
					continue
				}
				if !yield(span{m[0], m[1]}) {
					return
				}
			}
		}
	}
}

type urlPart struct{ url, host span }

func urlParts(s string) []urlPart {
	if !strings.Contains(s, "://") {
		return nil
	}
	var parts []urlPart
	for _, m := range schemes.FindAllStringIndex(s, -1) {
		if len(parts) > 0 && m[0] < parts[len(parts)-1].url.to {
			continue
		}
		end := m[1] + indexOrLen(s[m[1]:], urlEnds)
		authority := m[1] + indexOrLen(s[m[1]:end], "/?#")
		parts = append(parts, urlPart{url: span{m[0], end}, host: span{m[1], m[1] + indexOrLen(s[m[1]:authority], ":")}})
	}
	return parts
}

func indexOrLen(s, chars string) int {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return i
	}
	return len(s)
}

func credentialWordBefore(s string) int {
	if s == "" {
		return 0
	}
	last := s[len(s)-1] | 0x20
	for _, w := range credentialWords {
		if w[len(w)-1] == last && len(s) >= len(w) && strings.EqualFold(s[len(s)-len(w):], w) {
			return len(w)
		}
	}
	return 0
}

func containsFold(s, word string) bool {
	for i := 0; i+len(word) <= len(s); i++ {
		if s[i]|0x20 == word[0] && strings.EqualFold(s[i:i+len(word)], word) {
			return true
		}
	}
	return false
}

func after(measure func(string) (keep, n int)) func([]span, string, int) []span {
	return func(dst []span, s string, end int) []span {
		if keep, n := measure(s[end:]); n > 0 {
			dst = append(dst, span{end + keep, end + keep + n})
		}
		return dst
	}
}

func flagValueSpans(dst []span, s string, at int) []span {
	if strings.HasPrefix(s[at+quotesLen(s[at:]):], "-") {
		return dst
	}
	return valueSpans(dst, s, at)
}

func valueSpans(dst []span, s string, at int) []span {
	v := s[at+quotesLen(s[at:]):]
	if v == "" || strings.IndexByte(wordEnds, v[0]) >= 0 || isDotOrHomePath(v) {
		return dst
	}
	if quoteLen(s[at:]) > 0 {
		closing := at + 1 + indexOrLen(s[at+1:], s[at:at+1]+"\n")
		dst = maskRuns(dst, s, at, closing, shellBytes)
		at = closing
	}
	return maskRuns(dst, s, at, at+indexOrLen(s[at:], wordEnds), literalBytes)
}

func elementSpans(dst []span, a string) []span {
	v := a[quotesLen(a):]
	if v == "" || v[0] == '-' || isDotOrHomePath(v) {
		return dst
	}
	return maskRuns(dst, a, 0, len(a), literalBytes)
}

func maskRuns(dst []span, s string, from, to int, literal string) []span {
	for i := from; i < to; {
		if strings.IndexByte(literal, s[i]) >= 0 {
			i++
			continue
		}
		j := i + 1
		for j < to && strings.IndexByte(literal, s[j]) < 0 {
			j++
		}
		dst = append(dst, span{i, j})
		i = j
	}
	return dst
}

func isLiteral(c byte) bool { return strings.IndexByte(literalBytes, c) >= 0 }

func applySpans(s string, spans []span) string {
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.from])
		b.WriteString(mask)
		last = sp.to
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func namedValueSpans(dst []span, s string, end int) []span {
	if s[end-1] == ':' && end > len(hostWord) && strings.EqualFold(s[end-1-len(hostWord):end-1], hostWord) && isPort(s[end:]) {
		return dst
	}
	return valueSpans(dst, s, end)
}

func authorizationSpans(dst []span, s string, end int) []span {
	lead := end + quotesLen(s[end:])
	if n := schemeWordLen(s[lead:]); n > 0 {
		next := lead + n + blankLen(s[lead+n:])
		if next == lead+n {
			return dst
		}
		return valueSpans(dst, s, next)
	}
	before := len(dst)
	if dst = valueSpans(dst, s, end); len(dst) == before || quoteLen(s[end:]) > 0 {
		return dst
	}
	firstEnd := end + indexOrLen(s[end:], wordEnds)
	next := firstEnd + blankLen(s[firstEnd:])
	if next == firstEnd {
		return dst
	}
	secondEnd := next + indexOrLen(s[next:], wordEnds)
	if closesHeader(s[next:secondEnd], s[secondEnd:]) {
		dst = valueSpans(dst, s, next)
	}
	return dst
}

func userinfoSpans(dst []span, s string, end int) []span {
	authority := end + indexOrLen(s[end:], authorityEnds)
	if at := strings.LastIndexByte(s[end:authority], '@'); at > 0 {
		dst = maskRuns(dst, s, end, end+at, literalBytes)
	}
	return dst
}

func maskCurlUsers(s string) string {
	var spans []span
	underCurl, valueNext := false, false
	for i := 0; i < len(s); {
		if strings.IndexByte(segmentBreaks, s[i]) >= 0 {
			underCurl, valueNext = false, false
			i++
			continue
		}
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		word := s[i : i+wordLen(s[i:])]
		at := -1
		switch {
		case valueNext:
			at, valueNext = 0, false
		case isUserFlag(word):
			valueNext = underCurl
		case isCurl(word):
			underCurl = true
		case underCurl:
			if a := attachedUserValue(word); a > 0 {
				at = a
			}
		}
		if at >= 0 {
			spans = userPassSpans(spans, s, i+at)
		}
		i += len(word)
	}
	return applySpans(s, spans)
}

// isDotOrHomePath leaves out an absolute path: a base64 secret can start
// with a slash.
func isDotOrHomePath(v string) bool {
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") || strings.HasPrefix(v, "~/") {
		return true
	}
	for _, w := range []string{"..", ".", "~"} {
		if v == w || strings.HasPrefix(v, w) && isLiteral(v[len(w)]) {
			return true
		}
	}
	return false
}

func userPassSpans(dst []span, s string, at int) []span {
	name := at + quoteLen(s[at:])
	name += runLen(s[name:], userNamePunct)
	if name == len(s) || s[name] != ':' {
		return dst
	}
	return maskRuns(dst, s, name+1, name+1+indexOrLen(s[name+1:], wordEnds), literalBytes)
}

func accessKeyIDSpan(s string) (keep, n int) {
	if len(s) < accessKeyIDTail || strings.Trim(s[:accessKeyIDTail], "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" ||
		len(s) > accessKeyIDTail && (isAlnum(s[accessKeyIDTail]) || s[accessKeyIDTail] == '_') {
		return 0, 0
	}
	return 0, accessKeyIDTail
}

func prefixedSpan(s string) (keep, n int) {
	if n = runLen(s, prefixedPunct); n < minPrefixedTail {
		return 0, 0
	}
	return 0, n
}

func isUserFlag(word string) bool { return word == "-u" || word == "--user" }

func attachedUserValue(word string) int {
	switch {
	case strings.HasPrefix(word, "--user="):
		return len("--user=")
	case len(word) > 2 && strings.HasPrefix(word, "-u") && word[2] != '-':
		return len("-u")
	default:
		return 0
	}
}

func isCurl(word string) bool {
	word = strings.Trim(word, `"'`)
	word = word[strings.LastIndexAny(word, `/\`)+1:]
	return strings.EqualFold(word, "curl") || strings.EqualFold(word, "curl.exe")
}

func schemeWordLen(v string) int {
	for _, scheme := range []string{"bearer", "basic", "token", "digest"} {
		if len(v) >= len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) && (len(v) == len(scheme) || isLiteral(v[len(scheme)])) {
			return len(scheme)
		}
	}
	return 0
}

func isPort(v string) bool {
	digits := len(v) - len(strings.TrimLeft(v, "0123456789"))
	return digits > 0 && (digits == len(v) || !isAlnum(v[digits]))
}

func closesHeader(word, rest string) bool {
	return !strings.Contains(word, "://") && (strings.ContainsAny(word, `"'`) || rest == "" || rest[0] == '\n')
}

func firstWord(s string) string {
	s = strings.TrimLeft(s, " \t")
	return s[:wordLen(s)]
}

func wordLen(s string) int {
	n := 0
	for n < len(s) && s[n] != ' ' && s[n] != '\t' && strings.IndexByte(segmentBreaks, s[n]) < 0 {
		n++
	}
	return n
}

func quotesLen(s string) int {
	n := 0
	for n < len(s) && (s[n] == '"' || s[n] == '\'') {
		n++
	}
	return n
}

func quoteLen(s string) int {
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		return 1
	}
	return 0
}

func blankLen(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }

func runLen(s, punct string) int {
	n := 0
	for n < len(s) && (isAlnum(s[n]) || strings.IndexByte(punct, s[n]) >= 0) {
		n++
	}
	return n
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
