package ingest

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/store"
)

// commandMaxBodyBytes bounds POST /ingest/commands. A poll carries no
// payload at all, so this is small on purpose: it exists to stop a body
// being read, not to size one.
const commandMaxBodyBytes = 1024

// commandTTL is how long a minted command stays deliverable (owner,
// 2026-09-14, recorded on #48 and #32): ten minutes on birdcage's clock,
// never the canary's. A command the agent does not collect inside that
// window is simply never delivered -- #46 re-orders the self-test rather
// than birdcage holding one open indefinitely.
const commandTTL = 10 * time.Minute

// commandPoll is POST /ingest/commands' body. It has no fields: the
// canary is the token's, and a poll asks one question. It exists so a
// body that is present but not "{}" is rejected rather than ignored --
// an agent sending something birdcage does not understand should be told
// so while it is still cheap to fix, not have it silently dropped.
type commandPoll struct{}

// deliveredCommand is one command on the wire. The database id is
// included so the agent can report against it later and so an operator
// tracing a self-test has one identifier on both sides. ExpiresAt is
// sent so the agent can decline to act on a command it collected and
// then sat on -- birdcage's clock is authoritative, but a canary that
// knows the deadline can fail closed without asking.
type deliveredCommand struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Params    json.RawMessage `json:"params,omitempty"`
	ExpiresAt string          `json:"expires_at"`
}

// handleCommands serves POST /ingest/commands, reached only through
// requireBearerToken: issue #32 slice 5b, the command endpoint. The agent
// (#48) polls it every 60 seconds with jitter; birdcage never connects to
// a canary, so this is the only direction a command can travel.
//
// POST rather than GET deliberately. Collecting a command changes state
// -- it is marked delivered -- and a GET that mutates is a GET that
// caches, retries and gets prefetched.
//
// "Nothing for you" is 200 with a null command, not 404: an empty queue
// is the ordinary answer to a well-formed question, and reserving the 4xx
// range for things that are actually wrong keeps the agent's error
// handling (and #45's health signals) meaningful.
func (h *ingestHandler) handleCommands(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleCommands reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, commandMaxBodyBytes)
	var body commandPoll
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	// An empty body is the normal poll; "{}" is accepted too, so an agent
	// that always sends a JSON object is not a special case.
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeIngestError(w, http.StatusBadRequest, "malformed command poll body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed command poll body: trailing data")
		return
	}

	// tok.CanaryID, never anything from the request: a canary can only
	// ever be handed its own commands -- and, since issue #116, only the
	// command kinds its own kind implements (commandKindsFor).
	now := h.now().UTC()
	cmd, err := store.ClaimNextCanaryCommandOfKinds(r.Context(), h.db, tok.CanaryID, commandKindsFor(tok.Kind), now)
	if err != nil {
		if errors.Is(err, store.ErrCommandNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{"command": nil})
			return
		}
		slog.Error("ingest: claim canary command failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	if cmd.Kind == store.CommandScan {
		h.advanceClaimedScan(r, tok.CanaryID, cmd, now)
	}

	// Past this line the command is already marked delivered. If writing
	// the response fails the command is lost, not repeated -- #32's
	// stated preference: "a lost command is a retry; a doubled one is two
	// self-test sweeps or two upgrades."
	out := deliveredCommand{
		ID:        cmd.ID,
		Kind:      string(cmd.Kind),
		ExpiresAt: cmd.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	if cmd.Params != "" {
		// Valid JSON by MintCanaryCommand's check, which is the only way
		// a row gets into this table.
		out.Params = json.RawMessage(cmd.Params)
	}
	writeJSON(w, http.StatusOK, map[string]any{"command": out})
}

// commandKindsFor is the kind-to-command allow-list (issue #116): a
// honeypot claims only selftest, a scanner only scan. Any other kind
// gets an empty, non-nil set -- nothing is claimable -- so a kind added
// to the route without a line here fails closed.
func commandKindsFor(kind agentkind.Kind) map[store.CommandKind]bool {
	switch kind {
	case agentkind.Honeypot:
		return map[store.CommandKind]bool{store.CommandSelfTest: true}
	case agentkind.Scanner:
		return map[store.CommandKind]bool{store.CommandScan: true}
	}
	return map[store.CommandKind]bool{}
}

// advanceClaimedScan moves a just-claimed scan command's run to stage
// collected (ADR-0012 decision 9). Best-effort: the command is already
// delivered, and a stage is only a description of an unanswered run --
// nothing settles on it -- so a failure here is logged, never turned
// into a failed poll.
func (h *ingestHandler) advanceClaimedScan(r *http.Request, canaryID string, cmd store.CanaryCommand, now time.Time) {
	var params store.ScanParams
	if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil || params.RunID == "" {
		slog.Error("ingest: claimed scan command carries no run id", "canary", canaryID, "command_id", cmd.ID)
		return
	}
	if _, err := store.AdvanceRunStage(r.Context(), h.db, canaryID, params.RunID, store.StageCollected, now); err != nil {
		slog.Error("ingest: advance scan run to collected", "canary", canaryID, "command_id", cmd.ID, "err", err)
	}
}
