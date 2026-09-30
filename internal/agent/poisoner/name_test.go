package poisoner

import (
	"strings"
	"testing"
)

// TestNeighbourNamesKeepsTheOperatorsStyle is issue #86 decision 31's own
// worked example and the rules it implies: the same prefix, the same number
// of digits, a nearby number, and never the canary's own name.
func TestNeighbourNamesKeepsTheOperatorsStyle(t *testing.T) {
	tests := []struct {
		hostname string
		prefix   string
		width    int
	}{
		{hostname: "fs-lon-03", prefix: "fs-lon-", width: 2},
		{hostname: "FS-LON-03", prefix: "fs-lon-", width: 2},
		{hostname: "print07", prefix: "print", width: 2},
		{hostname: "app1", prefix: "app", width: 1},
		{hostname: "srv-0042", prefix: "srv-", width: 4},
		// A fully qualified name contributes its first label only: a
		// single-label LLMNR query for fs-lon-02.corp.example would be no
		// kind of disguise.
		{hostname: "fs-lon-03.corp.example", prefix: "fs-lon-", width: 2},
	}

	for _, tc := range tests {
		t.Run(tc.hostname, func(t *testing.T) {
			got, err := neighbourNames(tc.hostname, derivedNameCount, 99)
			if err != nil {
				t.Fatalf("neighbourNames: %v", err)
			}
			if len(got) != derivedNameCount {
				t.Fatalf("got %d names, want %d", len(got), derivedNameCount)
			}
			own := strings.ToLower(strings.SplitN(tc.hostname, ".", 2)[0])
			seen := map[string]bool{}
			for _, name := range got {
				if !strings.HasPrefix(name, tc.prefix) {
					t.Errorf("%q does not keep the prefix %q", name, tc.prefix)
				}
				if digits := name[len(tc.prefix):]; len(digits) != tc.width {
					t.Errorf("%q has %d digits, want %d -- the width must not change", name, len(digits), tc.width)
				}
				if name == own {
					t.Errorf("%q is the canary's own name", name)
				}
				if seen[name] {
					t.Errorf("%q appears twice", name)
				}
				seen[name] = true
				if _, err := normaliseName(name); err != nil {
					t.Errorf("%q is not a usable bait name: %v", name, err)
				}
			}
		})
	}
}

// TestNeighbourNamesIsStablePerSeed proves a canary keeps the same derived
// names across a restart, and that two canaries with different seeds do not
// have to share a pair. Issue #86 decision 33's "seeded per canary" is about
// the rhythm; the names are seeded from the same identity for the same
// reason.
func TestNeighbourNamesIsStablePerSeed(t *testing.T) {
	first, err := neighbourNames("fs-lon-03", 2, 12345)
	if err != nil {
		t.Fatalf("neighbourNames: %v", err)
	}
	again, err := neighbourNames("fs-lon-03", 2, 12345)
	if err != nil {
		t.Fatalf("neighbourNames again: %v", err)
	}
	if strings.Join(first, ",") != strings.Join(again, ",") {
		t.Errorf("the same seed gave %v then %v", first, again)
	}

	// Over a spread of seeds, at least two different pairs must appear --
	// otherwise the seed is not reaching the choice at all.
	pairs := map[string]bool{}
	for seed := uint64(0); seed < 40; seed++ {
		names, err := neighbourNames("fs-lon-03", 2, seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		pairs[strings.Join(names, ",")] = true
	}
	if len(pairs) < 2 {
		t.Errorf("every seed produced the same pair %v", pairs)
	}
}

// TestNeighbourNamesRefusesWhatItCannotStyle covers the hostnames that
// cannot yield a sibling in the operator's own style. Inventing one in some
// other style is the giveaway decision 31 exists to avoid, so the right
// answer is to refuse.
func TestNeighbourNamesRefusesWhatItCannotStyle(t *testing.T) {
	for _, hostname := range []string{
		"",           // nothing to work from
		"fileserver", // no trailing number
		"0042",       // all digits: no prefix to keep
		".",          // an empty first label
	} {
		t.Run(hostname, func(t *testing.T) {
			if got, err := neighbourNames(hostname, 2, 1); err == nil {
				t.Fatalf("neighbourNames(%q) returned %v", hostname, got)
			}
		})
	}
}

// TestNeighbourNamesKeepsTheDigitWidth is the awkward end of the width rule:
// a number near the top of its width must not widen, and one near zero must
// not go negative.
func TestNeighbourNamesKeepsTheDigitWidth(t *testing.T) {
	for _, hostname := range []string{"host98", "host01", "host00", "host9"} {
		t.Run(hostname, func(t *testing.T) {
			names, err := neighbourNames(hostname, 2, 7)
			if err != nil {
				t.Fatalf("neighbourNames(%q): %v", hostname, err)
			}
			want := len(hostname) // same prefix, same width, so same length
			for _, name := range names {
				if len(name) != want {
					t.Errorf("%q is %d characters, want %d -- the width changed", name, len(name), want)
				}
			}
		})
	}
}

// TestDeriveNamesAlwaysIncludesWPAD is decision 31's other half: wpad is
// always in the rotation, whether or not the operator supplied names.
func TestDeriveNamesAlwaysIncludesWPAD(t *testing.T) {
	operator, err := func() (Names, error) {
		names, _, err := ParseNames("old-fs-01,printer-7")
		return names, err
	}()
	if err != nil {
		t.Fatalf("ParseNames: %v", err)
	}

	withOperator, warning := DeriveNames("fs-lon-03", operator, 1)
	if warning != "" {
		t.Errorf("unexpected warning with operator names: %s", warning)
	}
	if !withOperator.contains(WPADName) {
		t.Errorf("operator names %v do not include %q", withOperator, WPADName)
	}
	if len(withOperator) != len(operator)+1 {
		t.Errorf("got %d names, want the operator's %d plus wpad", len(withOperator), len(operator))
	}
	if withOperator[len(withOperator)-1] != WPADName {
		t.Errorf("%q is not last: a reader must be able to tell it from the operator's own names", WPADName)
	}

	derived, warning := DeriveNames("fs-lon-03", nil, 1)
	if warning != "" {
		t.Errorf("unexpected warning with a derivable hostname: %s", warning)
	}
	if !derived.contains(WPADName) {
		t.Errorf("derived names %v do not include %q", derived, WPADName)
	}
	if len(derived) != derivedNameCount+1 {
		t.Errorf("got %d derived names, want %d plus wpad", len(derived), derivedNameCount)
	}
}

// TestDeriveNamesFallsBackToWPADAlone is the hostname nothing can be derived
// from: the rotation is wpad by itself, and the operator is told to supply
// names rather than left to guess why the bait is thin.
func TestDeriveNamesFallsBackToWPADAlone(t *testing.T) {
	names, warning := DeriveNames("fileserver", nil, 1)
	if len(names) != 1 || names[0] != WPADName {
		t.Errorf("got %v, want just %q", names, WPADName)
	}
	if warning == "" {
		t.Error("no warning: an operator whose bait is one protocol name must be told")
	}
	if strings.Contains(warning, WPADName) {
		// Not a secret in itself, but the rule is absolute and easier to
		// keep that way: no warning in this package names a bait name.
		t.Errorf("the warning names a bait name: %q", warning)
	}
}

// TestDeriveNamesDoesNotWriteIntoTheOperatorsSlice guards the append: a
// Names value handed in by a caller must not have wpad written into its own
// backing array.
func TestDeriveNamesDoesNotWriteIntoTheOperatorsSlice(t *testing.T) {
	backing := make(Names, 1, 4)
	backing[0] = "old-fs-01"
	got, _ := DeriveNames("fs-lon-03", backing, 1)
	if len(backing) != 1 {
		t.Fatalf("the caller's slice grew to %v", backing)
	}
	if cap(backing) > 1 && len(backing[:cap(backing)]) > 1 && backing[:cap(backing)][1] == WPADName {
		t.Error("wpad was written into the caller's backing array")
	}
	if len(got) != 2 {
		t.Errorf("got %v, want the operator's name plus wpad", got)
	}
}

// TestParseNames is the operator-supplied list: what it keeps, what it
// refuses, and that it never hands a refused name back to be logged.
func TestParseNames(t *testing.T) {
	tests := []struct {
		raw         string
		want        Names
		wantRefused int
		wantErr     bool
	}{
		{raw: "", want: nil},
		{raw: "old-fs-01", want: Names{"old-fs-01"}},
		{raw: " OLD-FS-01 , printer-7 ", want: Names{"old-fs-01", "printer-7"}},
		{raw: "a,b,c", want: Names{"a", "b", "c"}},
		// A fourth name is refused rather than silently dropped, so the
		// operator learns their list was too long.
		{raw: "a,b,c,d", want: Names{"a", "b", "c"}, wantRefused: 1},
		// Duplicates change nothing on the wire, so they are not refusals.
		{raw: "a,A,a", want: Names{"a"}},
		{raw: "-nope", wantRefused: 1, wantErr: true},
		{raw: "nope-", wantRefused: 1, wantErr: true},
		{raw: "has space", wantRefused: 1, wantErr: true},
		{raw: "under_score", wantRefused: 1, wantErr: true},
		{raw: "dots.are.a.domain", wantRefused: 1, wantErr: true},
		{raw: strings.Repeat("a", maxBaitNameLen+1), wantRefused: 1, wantErr: true},
		// One good and one bad: the good one is kept, the bad one counted.
		{raw: "old-fs-01,bad_name", want: Names{"old-fs-01"}, wantRefused: 1},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, refused, err := ParseNames(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want an error: %v", err, tc.wantErr)
			}
			if refused != tc.wantRefused {
				t.Errorf("refused %d, want %d", refused, tc.wantRefused)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if err != nil {
				// The error may say how many names were refused and what
				// the rule is; it must never quote one back.
				for _, field := range strings.Split(tc.raw, ",") {
					field = strings.TrimSpace(field)
					if field != "" && strings.Contains(err.Error(), field) {
						t.Errorf("the error quotes the refused name %q: %s", field, err)
					}
				}
			}
		})
	}
}

// TestParseNamesHoldsToTheNetBIOSLimit pins the length rule to the tightest
// of the three protocols, because a name that cannot be asked over NBT-NS
// could only be asked on two of them -- itself a distinguishing shape.
func TestParseNamesHoldsToTheNetBIOSLimit(t *testing.T) {
	if maxBaitNameLen != nbnsNamePadLen {
		t.Fatalf("maxBaitNameLen is %d, want NetBIOS' %d", maxBaitNameLen, nbnsNamePadLen)
	}
	atLimit, _, err := ParseNames(strings.Repeat("a", maxBaitNameLen))
	if err != nil || len(atLimit) != 1 {
		t.Errorf("a %d-character name was refused: %v", maxBaitNameLen, err)
	}
	if _, err := encodeNBNSQuery(1, atLimit[0]); err != nil {
		t.Errorf("a name ParseNames accepted cannot be NBT-NS encoded: %v", err)
	}
}
