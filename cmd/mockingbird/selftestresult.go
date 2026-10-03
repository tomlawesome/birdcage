package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// LogTypeSelfTestResult is birdcage's own logtype for an agent's report of
// how one self-test target turned out (#86 slice C, logtype 30002 --
// internal/opencanary/service.go holds the reasoning for the 30000 band and
// maps this value to the service name "selftest").
const LogTypeSelfTestResult = 30002

// Self-test outcomes. Two values, because a target whose pass is silence
// has exactly two things worth saying.
const (
	// selfTestOutcomeSilence is the pass: the probe went out and nothing
	// answered. For #86's poisoner target that is the correct outcome --
	// the names it asks for do not exist, so the only right answer is
	// none.
	selfTestOutcomeSilence = "silence"

	// selfTestOutcomeAnswered is the failure, and the worst one there is:
	// something on the segment answered a name that does not exist. The
	// alert for it has already gone out separately, through the ordinary
	// event path; this only records how the self-test itself turned out.
	selfTestOutcomeAnswered = "answered"
)

// openCanaryTimeLayout is the timestamp format OpenCanary writes into every
// event -- see internal/agent/portscan/event.go's constant of the same name
// for why every road reproduces it rather than using RFC 3339.
const openCanaryTimeLayout = "2006-01-02 15:04:05.000000"

// selfTestResultEvent is one self-test result, in OpenCanary's own JSON
// shape.
//
// Same eight top-level fields, in the same alphabetical declaration order,
// as every other road's event and for the same reason: encoding/json emits
// struct fields in declaration order and OpenCanary emits
// json.dumps(sort_keys=True), so declaring them already sorted is how a Go
// struct reproduces a Python sorted-keys dump.
//
// There is no source or destination to name. A self-test result is this
// canary talking about itself, not a visitor, so SrcHost and DstHost are
// deliberately left empty rather than filled with the canary's own address
// -- which would read, to anything that looked at it, like the canary had
// visited itself.
type selfTestResultEvent struct {
	DstHost   string              `json:"dst_host"`
	DstPort   int                 `json:"dst_port"`
	LocalTime string              `json:"local_time"`
	LogData   selfTestResultLogda `json:"logdata"`
	LogType   int                 `json:"logtype"`
	NodeID    string              `json:"node_id"`
	SrcHost   string              `json:"src_host"`
	SrcPort   int                 `json:"src_port"`
	UTCTime   string              `json:"utc_time"`
}

// selfTestResultLogda is the event's logdata object. Upper-case keys,
// declared sorted, for the reasons above.
type selfTestResultLogda struct {
	// MARKER is the marker birdcage minted for this target in this run.
	// It is in the payload because that is where birdcage looks for it:
	// store.SelfTestIndex.match is a substring search over the whole raw
	// event, so a marker anywhere inside it is found, and logdata is
	// where an OpenCanary event's own content lives.
	//
	// Not the ingest envelope's self_test_marker field, which means
	// something else: that field is an attributed-grade *claim* the agent
	// makes about another event, corroborated by MatchSelfTestClaim. This
	// is not a claim about anything else -- it is the event itself.
	MARKER string `json:"MARKER"`

	// OUTCOME is selfTestOutcomeSilence or selfTestOutcomeAnswered.
	OUTCOME string `json:"OUTCOME"`

	// TARGET is the service the result is about ("poisoner"), so one
	// shape serves whatever later target needs it.
	TARGET string `json:"TARGET"`
}

// encodeSelfTestResult renders one result as the exact bytes to hash into
// the event id and queue. Nothing re-serialises these bytes afterwards --
// the same contract every other road's encode states.
func encodeSelfTestResult(target, outcome, marker, nodeID string, now time.Time) ([]byte, error) {
	stamp := now.UTC().Format(openCanaryTimeLayout)
	body, err := json.Marshal(selfTestResultEvent{
		LocalTime: stamp,
		LogData: selfTestResultLogda{
			MARKER:  marker,
			OUTCOME: outcome,
			TARGET:  target,
		},
		LogType: LogTypeSelfTestResult,
		NodeID:  nodeID,
		UTCTime: stamp,
	})
	if err != nil {
		return nil, fmt.Errorf("encode self-test result: %w", err)
	}
	return body, nil
}

// selfTestResultService is the service name these events land under. Read
// from internal/opencanary rather than written out again, so this package
// cannot claim a name the ingest side no longer derives.
func selfTestResultService() string {
	logType := LogTypeSelfTestResult
	return opencanary.ServiceForLogType(&logType)
}

// selfTestNodeID is the node id a self-test result event is attributed to.
//
// Read from OpenCanary's configuration the same way every other road reads
// it, and falling back the same way: the value only groups the event with
// the rest of this box's own, and birdcage attributes the event to a canary
// from the bearer token regardless (#32: "the canary is the token's,
// whatever the body says"), so a wrong node id here cannot misattribute
// anything.
//
// Read per call rather than cached: a self-test runs at most twice a day,
// so one small file read is cheaper than a second place for this value to
// go stale.
func selfTestNodeID() string {
	path := os.Getenv(envOpenCanaryConf)
	if path == "" {
		path = poisoner.DefaultConfPath
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return poisoner.DefaultNodeID
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return poisoner.DefaultNodeID
	}
	var id string
	if err := json.Unmarshal(fields["device.node_id"], &id); err != nil || id == "" {
		return poisoner.DefaultNodeID
	}
	return id
}
