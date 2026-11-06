package cli

import (
	"slices"
	"strings"
)

// closestCommand returns the hop command nearest to word, or "" when none is
// near: within two edits, or one that word is a prefix of.
func closestCommand(word string) string {
	names := []string{"help", "version"}
	for n := range commands {
		names = append(names, n)
	}
	slices.Sort(names) // a tie goes to the first name, whatever the map order
	best, bestDist := "", 3
	for _, n := range names {
		d := editDistance(word, n)
		if len(word) >= 2 && strings.HasPrefix(n, word) {
			d = min(d, 1)
		}
		if d < bestDist {
			best, bestDist = n, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b, in bytes.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// unknownCommand is the failure for `hop word more...`: the first word is not
// a command, so hop would have treated it as a target, and a target takes no
// arguments after it.
func unknownCommand(word string) error {
	msg := safef(`unknown command "%s"`, word)
	if near := closestCommand(word); near != "" {
		msg += safef(` (did you mean "%s"?)`, near)
	}
	return failf("%s; hop <target> takes exactly one target, so more words after a name that is not a command are not accepted (hop -h lists the commands)", msg)
}
