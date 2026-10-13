package report

// Plural returns "" for n == 1 and "s" otherwise, the shared suffix every
// reporter's incomplete-sources line uses.
func Plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// PluralNoun returns singular for n == 1 and plural otherwise, for a noun
// whose plural is not simply singular+"s".
func PluralNoun(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
