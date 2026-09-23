package probe

import "context"

// carrierFunc opens a connection to address:port and plants marker
// where that service's OpenCanary module will log it. A non-nil error
// is a network or protocol-level failure -- dial refused, handshake
// timed out -- never a judgement about whether the target accepted any
// credential. Every carrierFunc is expected to honor ctx's deadline for
// every blocking call it makes.
type carrierFunc func(ctx context.Context, address string, port int, marker string) error

// carriers maps birdcage's service name (internal/opencanary's mapping,
// as carried on the wire by selftest.Target.Service) to the carrier that
// plants a marker for it, or -- for vnc -- does whatever that service's
// own grade needs instead (see vnc.go's own doc comment). A service
// named by a target but absent here -- other than the notProbeable set
// below and attributionCarriers below -- gets StatusNoCarrier rather
// than a guess, per #46's instruction: "skip it and return a
// clearly-labelled outcome rather than guessing."
//
// vnc is #46 slice 2 (notes 19854/19855/19897): its challenge-marked
// HMAC is matched and claimed today (internal/store/selftest_vnc.go).
var carriers = map[string]carrierFunc{
	"ftp":      probeFTP,
	"telnet":   probeTelnet,
	"http":     probeHTTP,
	"snmp":     probeSNMP,
	"tftp":     probeTFTP,
	"sip":      probeSIP,
	"mysql":    probeMySQL,
	"mssql":    probeMSSQL,
	"postgres": probePostgres,
	"redis":    probeRedis,
	"rdp":      probeRDP,
	"ssh":      probeSSH,
	"vnc":      probeVNC,
}

// attributionCarriers maps the two "attributed" grade services (notes
// 19854/19855/19897) to their carrier: nothing attacker-supplied is
// logged for either, so instead of planting a marker they report what
// they sent, and probeOne hands that on as the outcome's Fact for
// cmd/mockingbird's claim window to watch for (#46 slice 3).
var attributionCarriers = map[string]attributionCarrierFunc{
	"ntp":      probeNTP,
	"portscan": probePortscan,
}

// Attributed reports whether service is one of the attributed-grade
// services -- the ones whose event carries no marker and is claimed by
// cmd/mockingbird's claim window instead, so the caller can open that
// window before the probe that produces the event runs.
func Attributed(service string) bool {
	_, ok := attributionCarriers[service]
	return ok
}

// notProbeable are the services #46 rules out of scope for this build:
// smb needs a real Samba audit VFS this build cannot provide (a deploy
// dependency, not a protocol limit -- see note 19797), and llmnr's own
// detector (#86) is a separate, not-yet-designed feature -- OpenCanary's
// own llmnr module stays permanently disabled per notes 20752/20767, so
// there is currently no live target for a carrier to trigger at all. A
// target naming one of these is reported as StatusNotProbeable; nothing
// is attempted, and it is never treated as StatusNoCarrier, so a log
// reader can tell "ruled out" apart from "this build doesn't know how
// yet."
var notProbeable = map[string]bool{
	"smb":   true,
	"llmnr": true,
}
