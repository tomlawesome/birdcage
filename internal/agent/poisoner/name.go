package poisoner

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Bait-name limits.
const (
	// maxBaitNameLen is fifteen characters, the width of a NetBIOS name
	// before its service suffix (RFC 1002 section 4.2.1.2). LLMNR and
	// mDNS would take a 63-byte label, but a name that cannot be asked
	// for on all three protocols is not a name this package can use, so
	// the tightest limit is the limit.
	maxBaitNameLen = nbnsNamePadLen

	// MaxOperatorNames is how many names an operator may supply. Issue
	// #86 decision 31: "two or three names in their own naming style".
	// A longer list is not more convincing, and every extra name is more
	// traffic from a host that is meant to look ordinary.
	MaxOperatorNames = 3

	// derivedNameCount is how many neighbours the generator invents when
	// the operator supplied none -- two, matching decision 31's worked
	// example (fs-lon-03 yielding fs-lon-02 and fs-lon-07).
	derivedNameCount = 2
)

// WPADName is the one name that is always in the rotation (issue #86
// decision 31). It is not an invented bait: every Windows client on a
// network with no WPAD DNS record asks for it, and Responder poisons it
// by name, so asking for it is both the most ordinary question on the
// segment and the one most likely to be answered.
//
// This is the only name in this package's source, and it is a protocol
// name rather than a host name, so it gives an attacker grepping the
// binary nothing about the operator's network.
const WPADName = "wpad"

// errNoName is returned when neither the operator nor the hostname could
// supply anything.
var errNoName = errors.New("poisoner: no usable bait name")

// Names is the rotation of names a canary asks for. WPADName is always
// the last entry, so a reader of a log or an event can tell the derived
// or operator-supplied names from the one this package adds itself.
type Names []string

// ParseNames reads an operator's comma-separated list, keeping at most
// MaxOperatorNames usable entries and reporting how many it refused.
//
// The refused count is all the caller gets back, deliberately: the
// rejected text is a bait name, and this package never lets one reach a
// log line (see the package comment). An operator who mistypes one sees
// that a name was refused and the rule it broke, not the name.
func ParseNames(raw string) (Names, int, error) {
	var names Names
	refused := 0
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		name, err := normaliseName(field)
		if err != nil {
			refused++
			continue
		}
		if names.contains(name) {
			// A duplicate is not a refusal worth reporting: it changes
			// nothing about what goes on the wire.
			continue
		}
		if len(names) >= MaxOperatorNames {
			refused++
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 && refused > 0 {
		return nil, refused, fmt.Errorf("poisoner: none of the %d supplied bait names is usable: a name must be 1 to %d characters of letters, digits and hyphens, and may not start or end with a hyphen", refused, maxBaitNameLen)
	}
	return names, refused, nil
}

// DeriveNames builds the rotation for a canary: the operator's names if
// they gave any, otherwise neighbours of the agent's own hostname, and
// WPADName either way.
//
// seed makes the derived neighbours stable for the life of a canary: the
// same seed picks the same neighbours after a restart, so a canary does
// not start asking for a different retired file server every time its
// container comes back.
//
// A hostname with no trailing number (`fileserver`, not `fs-lon-03`) is
// the one case where nothing can be derived in the operator's own style,
// and inventing one in some other style is exactly the giveaway decision
// 31 avoids -- so the rotation is WPADName alone, and the caller is told
// through the returned warning that supplying names would make the bait
// better.
func DeriveNames(hostname string, operator Names, seed uint64) (Names, string) {
	if len(operator) > 0 {
		return append(operator.clone(), WPADName), ""
	}

	derived, err := neighbourNames(hostname, derivedNameCount, seed)
	if err != nil {
		return Names{WPADName}, "no bait name could be derived from this canary's own hostname, so only the protocol name is in the rotation: " +
			"set the bait names at enrolment to give this detector names in your own naming style"
	}
	return append(derived, WPADName), ""
}

// neighbourNames derives count names that look like siblings of hostname:
// the same prefix, the same number of digits, a nearby number.
//
// `fs-lon-03` yields `fs-lon-02` and `fs-lon-07` in decision 31's own
// example, which is the rule: keep everything up to the trailing digits,
// keep the digits' width (so 03 never becomes 3 or 103), and move the
// number by a small offset.
func neighbourNames(hostname string, count int, seed uint64) (Names, error) {
	// Only the first label: a canary whose hostname is fully qualified
	// must not produce `fs-lon-02.corp.example` as a single-label LLMNR
	// name.
	host := strings.ToLower(strings.TrimSpace(hostname))
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil, errNoName
	}

	end := len(host)
	for end > 0 && host[end-1] >= '0' && host[end-1] <= '9' {
		end--
	}
	prefix, digits := host[:end], host[end:]
	if digits == "" || prefix == "" {
		// No trailing number to step, or a name that is nothing but
		// digits -- neither can produce a plausible sibling.
		return nil, errNoName
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return nil, errNoName
	}
	width := len(digits)

	// Offsets a plausible sibling sits at: the one just below, then
	// outward. Shuffled by the canary's own seed so two canaries on the
	// same segment with adjacent hostnames do not ask for the same pair.
	offsets := []int{-1, 1, 2, -2, 3, 4, -3, 5, 6, -4}
	r := rand.New(rand.NewPCG(seed, 0x5f86))
	r.Shuffle(len(offsets), func(i, j int) { offsets[i], offsets[j] = offsets[j], offsets[i] })

	var out Names
	for _, off := range offsets {
		if len(out) == count {
			break
		}
		m := n + off
		if m < 0 {
			continue
		}
		// Same style means same width: a two-digit scheme stays
		// two-digit, so 03 never yields 100 and 03 never yields 3.
		candidate := prefix + fmt.Sprintf("%0*d", width, m)
		if len(candidate)-len(prefix) != width {
			continue
		}
		name, err := normaliseName(candidate)
		if err != nil || name == host || out.contains(name) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errNoName
	}
	return out, nil
}

// normaliseName lower-cases and checks one bait name.
//
// The alphabet is the letter-digit-hyphen rule of RFC 1123 section 2.1,
// which is what a hostname an operator would actually have used looks
// like; it is also the safe intersection of what a DNS label, a NetBIOS
// name and an mDNS label all accept. The upper bound is
// maxBaitNameLen rather than a DNS label's 63, because a name that
// cannot be asked for over NBT-NS could only be asked for on two of the
// three protocols, which would itself be a distinguishing shape.
func normaliseName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", errNoName
	}
	if len(name) > maxBaitNameLen {
		return "", fmt.Errorf("poisoner: bait name is %d characters, over the %d-character limit", len(name), maxBaitNameLen)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return "", errors.New("poisoner: bait name starts or ends with a hyphen")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return "", errors.New("poisoner: bait name has a character outside letters, digits and hyphens")
		}
	}
	return name, nil
}

// contains reports whether names already holds name.
func (n Names) contains(name string) bool {
	for _, have := range n {
		if have == name {
			return true
		}
	}
	return false
}

// clone copies the slice so appending WPADName cannot write into a
// caller's backing array.
func (n Names) clone() Names {
	out := make(Names, len(n))
	copy(out, n)
	return out
}
