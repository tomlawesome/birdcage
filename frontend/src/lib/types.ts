// Shapes match the JSON the Go API sends -- snake_case field names, same
// convention as internal/api's existing routes (see alertsResponse's
// next_before). Defined here once so src/lib/api.ts and every later
// slice (the band, tiles, events) import the same types rather than
// each guessing the shape independently.

export type Lane = 'lan' | 'srv' | 'iot' | 'guest'
/** issue #45's ordered health state -- worst-first: token_conflict,
 * silent, not_delivering, throttled, rotation_stalled, ok. The other
 * three states the issue names (self_test_failed, pending,
 * agent_out_of_date) don't appear here yet: #46/#47/#48 haven't shipped
 * the data they'd read from. */
export type CanaryStatus = 'token_conflict' | 'silent' | 'not_delivering' | 'throttled' | 'rotation_stalled' | 'ok'
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
  hits: number
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
