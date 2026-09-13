// Shapes match the JSON the Go API sends -- snake_case field names, same
// convention as internal/api's existing routes (see alertsResponse's
// next_before). Defined here once so src/lib/api.ts and every later
// slice (the band, tiles, events) import the same types rather than
// each guessing the shape independently.

export type Lane = 'lan' | 'srv' | 'iot' | 'guest'
export type CanaryStatus = 'ok' | 'silent'
export type VisitorKind = 'sweep' | 'repeat' | 'inside' | 'touch'
export type Range = '15m' | '1h' | '24h' | '14d' | '90d'

/** GET /api/canaries' per-canary shape (issue #34). */
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

export interface TraceResponse {
  now: string
  range: Range
  canaries: TraceCanary[]
}
