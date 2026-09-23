// Shapes match the JSON the Go API sends -- snake_case field names, same
// convention as internal/api's existing routes (see alertsResponse's
// next_before). Defined here once so src/lib/api.ts and every later
// slice (the band, tiles, events) import the same types rather than
// each guessing the shape independently.

export type Lane = 'lan' | 'srv' | 'iot' | 'guest'
/** issue #45's ordered health state -- worst-first: token_conflict,
 * silent, not_delivering, self_test_failed, throttled, rotation_stalled,
 * pending, ok. 'pending' (issue #47 steps 7-9) is
 * provisioned-but-not-yet-registered: not a fault, not health -- #45's
 * own third category, outside both the critical and degraded tiers.
 * 'self_test_failed' (issue #46, health.go's StateTestFailed) ranks
 * between not_delivering and throttled, the slot health.go gives it. One
 * state the issue names, agent_out_of_date, still doesn't appear here:
 * #48 hasn't shipped the frontend data it would read from. */
export type CanaryStatus =
  | 'token_conflict'
  | 'silent'
  | 'not_delivering'
  | 'self_test_failed'
  | 'throttled'
  | 'rotation_stalled'
  | 'pending'
  | 'ok'
export type VisitorKind = 'sweep' | 'repeat' | 'inside' | 'touch'
export type Range = '15m' | '1h' | '24h' | '14d' | '90d'

/** GET /api/canaries' per-canary shape (issue #34, widened by #45). */
export interface Canary {
  id: string
  name: string
  lane: Lane
  ports: string
  status: CanaryStatus
  last_heartbeat_at: string | null
  /** Present only when status is 'silent'. */
  silent_for_s?: number
  beats_missed?: number
  /** issue #45: each of these can be set independently of which state
   * `status` reports -- "one state on the tile, the worst; the rest in
   * its detail." */
  not_delivering?: boolean
  throttled_for_s?: number
  rotation_stalled?: boolean
  rotation_stalled_for_s?: number
  rotation_stalled_escalated?: boolean
  token_conflict_for_s?: number
  /** issue #46: the most recently *completed* self-test run, or
   * null/undefined when none has ever completed (store/canary.go's
   * LastSelfTestAt/LastSelfTestPassed). SelfTestFailedServices names the
   * targets that never matched, populated only when
   * last_self_test_passed is false. */
  last_self_test_at?: string | null
  last_self_test_passed?: boolean
  self_test_failed_services?: string[]
  /** issue #46 slice 2: the most recently completed run's per-service
   * breakdown, absent entirely when no run has ever completed. The
   * canary page's ledger (#118) draws one card per entry. */
  self_test?: SelfTestServiceResult[]
  hits: number
}

/** How strong a passing self-test target's evidence is (#46's three
 * grades of proof, internal/store/selftest_grade.go). A service the run
 * never probed has no entry at all -- absence is how "untested" is
 * carried, which is why there is no third value here. */
export type SelfTestGrade = 'marked' | 'challenge_marked' | 'attributed'

/** One service's outcome in a canary's most recently completed self-test
 * run (GET /api/canaries' and GET /api/canary's `self_test` array). */
export interface SelfTestServiceResult {
  service: string
  grade: SelfTestGrade
  passed: boolean
}

export interface CanariesResponse {
  canaries: Canary[]
}

/** One touched canary within a GET /api/visitors entry. */
export interface VisitorCanaryHits {
  id: string
  hits: number
}

/** GET /api/visitors' per-visitor shape (issue #35). */
export interface Visitor {
  source_ip: string
  kind: VisitorKind
  first_at: string
  last_at: string
  hits: number
  canaries: VisitorCanaryHits[]
  services: string[]
  tried: string[]
  still_arriving: boolean
}

export interface VisitorsResponse {
  visitors: Visitor[]
  /** Cursor for the next page, same shape as /api/alerts' next_before. */
  next_before: string | null
}

/** One hit inside GET /api/trace's per-canary hit list (issue #35). */
export interface TraceHit {
  at: string
  visitor: string
  kind: VisitorKind
  service: string
  tried: string
}

/** GET /api/trace's per-canary shape (issue #35). */
export interface TraceCanary {
  id: string
  lane: Lane
  status: CanaryStatus
  last_heartbeat_at: string | null
  /** Heartbeats inside the last 15 minutes only. */
  beats: string[]
  hits: TraceHit[]
}

/** The single newest alert ever recorded, independent of range -- null
 * when the alerts table has never held a row (issue #39). Drives the
 * quiet-day story (lib/sentence/quietStory.ts) once a real API sits
 * behind /api/trace, since a range-scoped trace can't answer "quiet
 * since when" once that touch falls outside every range. */
export interface LastHit {
  at: string
  visitor: string
  canary: string
  port: number
  service: string
  kind: VisitorKind
}

export interface TraceResponse {
  now: string
  range: Range
  canaries: TraceCanary[]
  last_hit: LastHit | null
}

/** What a canary's history remembers: CanaryStatus's unhealthy states,
 * plus 'pending' (issue #47: provisioned but not yet registered -- not a
 * fault, not health, internal/history records every ActiveStates entry
 * so a pending stretch shows too) and 'unobserved' -- birdcage itself
 * was not watching, which is neither a fault of the canary's nor a clean
 * bill of health. */
export type HistoryState =
  | 'token_conflict'
  | 'silent'
  | 'not_delivering'
  | 'self_test_failed'
  | 'throttled'
  | 'rotation_stalled'
  | 'pending'
  | 'unobserved'

/** Why a period ended: the state cleared, a quiet period covered it, or
 * birdcage stopped watching. null while the period is still open. */
export type HistoryEndReason = 'cleared' | 'quiet_period' | 'unobserved'

/** One unbroken run of a state (issue #56). `ended_at` null means the
 * period is still open and runs to the response's `until`; flap_count
 * above 1 counts re-entries within ten minutes, collapsed into this one
 * span rather than drawn as a row of slivers. */
export interface HistoryPeriod {
  canary_id: string
  canary_name: string
  state: HistoryState
  started_at: string
  ended_at: string | null
  flap_count: number
  end_reason: HistoryEndReason | null
}

/** Per canary and state, the window's totals -- a row's one-line summary
 * is written from these, never counted off the periods (a period clipped
 * by the window edge would otherwise be counted at the wrong length). */
export interface HistorySummary {
  canary_id: string
  canary_name: string
  state: HistoryState
  count: number
  longest_s: number
  total_s: number
}

/** GET /api/mail (issue #55): whether outbound mail is configured, and
 * how the sending itself is going. Nothing here is a credential or
 * derived from one -- no host, no username, no address.
 *
 * `failing_since` is the created_at of the oldest message still owed
 * that has actually been tried, and `last_error` is that same message's
 * error, so the two always describe one failure. `suppressed` is how
 * many alerts birdcage's own rate limits deliberately did not send;
 * they are reported on the next message that does go out, never
 * dropped. */
export interface MailStatus {
  configured: boolean
  last_sent_at: string | null
  failing_since: string | null
  last_error: string | null
  pending: number
  suppressed: number
}

export interface HistoryResponse {
  range: Range
  since: string
  until: string
  periods: HistoryPeriod[]
  summary: HistorySummary[]
}

/** The standing facts about one canary (GET /api/canary's `facts`,
 * issue #118) -- what the canary page's right-hand column names and no
 * fleet read carries. Who enrolled it is deliberately not here: birdcage
 * has no operator identity yet (issue #8), so the API does not claim
 * one. */
export interface CanaryFacts {
  kind: string
  lane: string
  ports: string
  /** The peer address the canary's heartbeats arrive from, absent until
   * one has. */
  address?: string
  heartbeat_interval_s: number
  self_test_enabled: boolean
  /** 24-hour UTC "HH:MM" -- the schedule that actually applies, whether
   * that is the self-test's own or the rotation one it follows. */
  self_test_schedule: string
  enrolled_at: string
  registered_at?: string
  agent_version?: string
  /** The bait names the poisoner detector is asking for (#86 slice D),
   * comma-separated, as the agent last reported them. Absent for a canary
   * that reports none: the detector off, an older agent, or a kind that is
   * not a honeypot. */
  poisoner_names?: string
  token_rotated_at?: string
  token_rotates_at?: string
}

/** One past self-test run, as the canary page's line draws it: a hollow
 * tick under the line per run, filled with words above when it failed.
 * `passed` is absent while a run is still inside its deadline. */
export interface SelfTestRunSummary {
  issued_at: string
  completed_at?: string
  passed?: boolean
  failed_services?: string[]
}

/** GET /api/canary?id=&range= (issue #118): one canary's own page. The
 * canary itself is exactly the shape /api/canaries sends for it, so the
 * page and its tile can never disagree about a status. */
export interface CanaryPageResponse {
  canary: Canary
  facts: CanaryFacts
  self_test_runs: SelfTestRunSummary[]
}
