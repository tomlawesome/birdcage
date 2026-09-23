// Package agentkind is issue #105's representation of what kind of agent
// an enrolled node is (ADR-0009: "an agent has a kind"). It is a leaf
// package -- it imports nothing else of birdcage's -- specifically so
// internal/store, internal/enrol, internal/ca and cmd/birdcage can all
// import it without creating a cycle. internal/enrol already imports
// internal/store, which is why store.mockingbirdPorts and
// enrol.MockingbirdPorts used to exist as two separately-maintained
// copies of the same constant; agentkind is the cycle-free home both
// mirrors move into.
package agentkind

// Kind is the closed set of agent kinds birdcage's control plane knows
// about -- kept in Go rather than a SQL CHECK constraint, the same
// reasoning store.CommandKind and store.EnrolmentState already use: the
// constraint would have to be written once per engine (sqlite, postgres)
// and would then disagree with this list the moment either changed.
//
// The set only changes with a code release -- a new kind ships a new
// image, new ingest routes and a new provisioning profile -- so a
// database lookup table would add a join and a drift surface with
// nothing to buy.
type Kind string

// Honeypot is the first registered kind (#105) and, until ADR-0010's
// scanner kind lands, the only one. Every node birdcage has ever
// enrolled is one of these, which is why migration 0013_agent_kinds.sql
// backfills every existing row to "honeypot" rather than leaving it
// unset.
//
// The string is "honeypot", not "mockingbird" (settled by the owner,
// 2026-09-22): kind is a *role* the fleet authorises on (ADR-0009
// decision 3, #106: "a honeypot cannot post vulnerability findings"),
// and #106 will carry this string into the client certificate long-term.
// "mockingbird" is the product name of the image that happens to
// implement the honeypot role today (DefaultImage below) -- a fact
// about this kind's profile, not the kind itself.
const Honeypot Kind = "honeypot"

// Scanner is the second registered kind (#108, ADR-0010's vulnerability
// agent), registered the moment its own first slice lands rather than
// merely reserved (ADR-0009 decision 2 named the string without
// registering it). The string stays "scanner" -- a role, matching
// Honeypot's own reasoning -- even though the owner named the product
// "Nightjar" (ADR-0010, "The agent is Nightjar"): "the kind is a role
// and the name is the product, exactly as mockingbird sits against
// honeypot".
const Scanner Kind = "scanner"

// Profile is what birdcage needs to know about a kind at provisioning
// time and at enrolment-run-command time. It lives in code, not the
// database (section 4 of the #105 delivery plan): a node's expected
// ports and image are facts about its kind's shipped image, versioned
// with the image, not operator data.
type Profile struct {
	// Ports is the fixed, comma-separated, ascending port list this
	// kind's image serves -- written into a provisioned node's canaries
	// row (store.Provision) since a node is never asked for its own
	// ports. For Honeypot this must match every `"*.enabled": true`
	// module's `.port` entry in build/mockingbird/opencanary.conf
	// exactly: ftp(21), ssh(22), telnet(23), tftp(69), http(80),
	// mssql(1433), mysql(3306), rdp(3389), sip(5060), redis(6379). A
	// change to that file must update this literal -- it is now the one
	// place this invariant is recorded; there is no longer a second
	// mirror to forget.
	Ports string

	// DefaultImage and ImageEnv are `birdcage canary enrol`'s image
	// selection for this kind: the image named by the environment
	// variable ImageEnv, or DefaultImage if that variable is unset.
	//
	// TODO(#69 registry): birdcage doesn't publish Honeypot's image
	// anywhere yet, so DefaultImage names a tag an operator has to build
	// and load by hand until #69 lands a real registry to pull it from.
	DefaultImage string
	ImageEnv     string
}

// profiles is Lookup's and Valid's backing store -- unexported so a
// caller cannot range over or mutate it directly, only ask about one
// kind at a time.
var profiles = map[Kind]Profile{
	Honeypot: {
		Ports:        "21,22,23,69,80,1433,3306,3389,5060,6379",
		DefaultImage: "mockingbird:latest",
		ImageEnv:     "MOCKINGBIRD_IMAGE",
	},
	// Scanner's Ports is deliberately "" -- #108's plan section 6:
	// "confirm store.Provision accepts an empty port list". Nightjar
	// listens on nothing (no receiver, no webhook, ADR-0010 decision 3),
	// so there is no port list to write, and the empty string round-trips
	// through canaries.ports (TEXT NOT NULL DEFAULT '') and portsDisplay
	// ("" -> "") without a schema or code change -- see
	// TestProvisionScannerAcceptsEmptyPorts in internal/store.
	Scanner: {
		Ports:        "",
		DefaultImage: "nightjar:latest",
		ImageEnv:     "NIGHTJAR_IMAGE",
	},
}

// Lookup returns k's provisioning profile, and false if k is not a
// registered kind. Callers on the write path (store.Provision) treat
// false as an invariant violation and fail loudly -- see that
// function's own doc comment; this package draws no such conclusion
// itself, since a read path (e.g. ListCanaries) must display an
// unrecognised kind, not crash on it.
func Lookup(k Kind) (Profile, bool) {
	p, ok := profiles[k]
	return p, ok
}

// Valid reports whether k is a registered kind. Write paths
// (MintEnrolmentSession, InsertCanary, and this package's own CLI
// flag validation) call this and refuse the write on false; read paths
// never call it, by design (see Lookup's doc comment).
func Valid(k Kind) bool {
	_, ok := profiles[k]
	return ok
}

// Kinds returns every registered kind, for callers that need to list
// the valid set -- e.g. `birdcage canary enrol --kind`'s error message
// when given an unrecognised value. The order is stable (declaration
// order below) rather than Go's randomised map iteration, so the same
// invalid input always produces the same error text.
func Kinds() []Kind {
	// Declared as a literal, not derived from profiles, so the order is
	// stable without needing a sort.
	return []Kind{Honeypot, Scanner}
}
