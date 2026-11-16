// Typed fetchers for the three dashboard reads (issues #34, #35). Every
// later slice (the band, tiles, events) calls these rather than
// building its own fetch/URLSearchParams boilerplate.
//
// Fixture mode: a dev build (`npm run dev`) with `?scene=quiet|silent|
// night` in the URL returns the matching fixture from src/dev/fixtures
// instead of calling the network -- lets the chrome and every later
// slice render against the round-6 data story without a running Go
// server. Never active in a production build: import.meta.env.DEV is
// inlined to `false` there, so fixtureScene() always returns null and
// loadFixture() is never called -- the fixture JSON still ships as
// unreachable lazy chunks (Vite code-splits every dynamic import
// regardless of reachability), but no production request ever fetches
// them.
import type {
  CanariesResponse,
  CanaryPageResponse,
  HistoryResponse,
  MailStatus,
  Range,
  RunsResponse,
  TraceResponse,
  VisitorsResponse,
} from './types'

/** A refused or failed request. `status` is the HTTP status. From
 * sendJSON, `kind` is the problem document's class -- the text after `#`
 * in its `type` (`invalid-credentials`, `rate-limited`, `step-expired`,
 * ...) -- and `detail` its free text, shown only where the sign-in
 * specification says so and never branched on; both are '' when the
 * body was not a problem document, and always '' from getJSON, which
 * does not read the body of a failure. The message is the method (from
 * sendJSON), the path and the status only: a request body never reaches
 * it. */
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public kind = '',
    public detail = '',
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

// Sign-in (issue #8, ADR-0016): a 401 from any dashboard read means the
// session ended or timed out. App.svelte registers the one handler that
// shows the door again; with none registered a 401 is only an error.
const noHandler = () => {}
let signedOutHandler: () => void = noHandler

/** Registers the handler a 401 from getJSON calls (the latest wins).
 * Returns the unsubscribe, which removes it if it is still the one
 * registered. */
export function onSignedOut(fn: () => void): () => void {
  signedOutHandler = fn
  return () => {
    if (signedOutHandler === fn) signedOutHandler = noHandler
  }
}

// gauntlet's CSRF guard: every POST, PUT, PATCH and DELETE must carry
// this header with birdcage's configured value, or it is refused 403.
const CSRF_HEADER = { 'X-Requested-With': 'birdcage' }

/** The problem class and detail of a failed response, or '' for both
 * when its body is not an RFC 9457 problem document. */
async function problemOf(res: Response): Promise<{ kind: string; detail: string }> {
  try {
    const body = (await res.json()) as { type?: unknown; detail?: unknown }
    const type = typeof body?.type === 'string' ? body.type : ''
    const hash = type.indexOf('#')
    return {
      kind: hash >= 0 ? type.slice(hash + 1) : '',
      detail: hash >= 0 && typeof body.detail === 'string' ? body.detail : '',
    }
  } catch {
    return { kind: '', detail: '' }
  }
}

/** Every request that changes something goes through here: the CSRF
 * header always, the JSON body (and its content type) when one is given,
 * nothing in the URL beyond the path. Returns the parsed JSON of a 2xx;
 * otherwise throws ApiError with the status, the problem's kind and its
 * detail. The reply's type is the caller's to name; unnamed, it is
 * any, as res.json() is. */
export async function sendJSON<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { ...CSRF_HEADER }
  const init: RequestInit = { method, headers, credentials: 'same-origin' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  const res = await fetch(path, init)
  if (!res.ok) {
    const { kind, detail } = await problemOf(res)
    throw new ApiError(`${method} ${path}: ${res.status}`, res.status, kind, detail)
  }
  const text = await res.text()
  return (text ? JSON.parse(text) : null) as T
}

interface Fixture {
  canaries: CanariesResponse
  visitors: VisitorsResponse
  trace: TraceResponse
  /** Only the 'history' scene carries one (issue #56): the older scenes
   * predate the endpoint, and a scene without history reads as a fleet
   * with nothing recorded yet, which is a state the section draws. */
  history?: HistoryResponse
  /** Only the round-7 canary scenes carry one (issue #118): the canary
   * page is reached from a tile, and a scene without the block is a
   * fleet scene that has no canary page to draw. Keyed by canary id, so
   * one scene can answer for whichever tile was opened. */
  canary?: Record<string, CanaryPageResponse>
  /** ADR-0012 (issue #116): a scanner's own scan-run history, keyed by
   * canary id, present only for a scene that has one. None of the
   * existing scenes are a scanner, so this is always absent today. */
  runs?: Record<string, RunsResponse>
  /** Every scene carries one (issue #55). Mail is off in all of them
   * except 'alerts', which is the scene where something has gone wrong
   * and is therefore where a broken mailer is worth showing. A scene
   * without the block reads as mail being off, the same as an instance
   * that never configured it. */
  mail?: MailStatus
}

type SceneName =
  | 'quiet'
  | 'silent'
  | 'night'
  | 'alerts'
  | 'history'
  // Issue #118's four round-7 canary scenes. Named for what the page
  // says, not for the fleet state, since that is what the scene is of:
  // one canary, quiet and answering; deaf on telnet; silent for the
  // third time this week; and the sweep night seen from this canary.
  | 'canary-quiet'
  | 'canary-failed'
  | 'canary-silent'
  | 'canary-night'
  // Issue #45's own gap: a scanner mid-proof, its ordered run open at
  // db_refreshed -- no fixture scene covered 'pending' before this. Not
  // wired into scripts/canary-compare.mjs's pixel gate: that would need
  // a captured baseline (docs/design/concepts/round-7/shots), which
  // nothing has judged by eye yet.
  | 'canary-pending'
  // Issue #54: an agent behind birdcage, and the same canary during the
  // upgrade window an accepted upgrade token opened. Not in the pixel
  // gate either, for the same reason as canary-pending.
  | 'canary-agent-out-of-date'
  | 'canary-upgrade-in-progress'
  // Issue #86 slice D's own scene: one poisoner answered a bait query.
  // Its own scene rather than a poisoner added to an existing one, so no
  // reference image that has already been reviewed moves.
  | 'poisoner'

const SCENES: SceneName[] = [
  'quiet',
  'silent',
  'night',
  'alerts',
  'history',
  'canary-quiet',
  'canary-failed',
  'canary-silent',
  'canary-night',
  'canary-pending',
  'canary-agent-out-of-date',
  'canary-upgrade-in-progress',
  'poisoner',
]

// Static imports (not a dynamic fetch of the JSON file) so a production
// build's tree-shaking can drop them entirely once the import.meta.env.DEV
// check above is compiled out.
async function loadFixture(scene: SceneName): Promise<Fixture> {
  switch (scene) {
    case 'quiet':
      return (await import('../dev/fixtures/quiet.json')) as unknown as Fixture
    case 'silent':
      return (await import('../dev/fixtures/silent.json')) as unknown as Fixture
    case 'night':
      return (await import('../dev/fixtures/night.json')) as unknown as Fixture
    case 'alerts':
      return (await import('../dev/fixtures/alerts.json')) as unknown as Fixture
    case 'history':
      return (await import('../dev/fixtures/history.json')) as unknown as Fixture
    case 'poisoner':
      return (await import('../dev/fixtures/poisoner.json')) as unknown as Fixture
    case 'canary-quiet':
      return (await import('../dev/fixtures/canary-quiet.json')) as unknown as Fixture
    case 'canary-failed':
      return (await import('../dev/fixtures/canary-failed.json')) as unknown as Fixture
    case 'canary-silent':
      return (await import('../dev/fixtures/canary-silent.json')) as unknown as Fixture
    case 'canary-night':
      return (await import('../dev/fixtures/canary-night.json')) as unknown as Fixture
    case 'canary-pending':
      return (await import('../dev/fixtures/canary-pending.json')) as unknown as Fixture
    case 'canary-agent-out-of-date':
      return (await import('../dev/fixtures/canary-agent-out-of-date.json')) as unknown as Fixture
    case 'canary-upgrade-in-progress':
      return (await import('../dev/fixtures/canary-upgrade-in-progress.json')) as unknown as Fixture
  }
}

function sceneFromLocation(): SceneName | null {
  if (typeof location === 'undefined') return null
  const scene = new URLSearchParams(location.search).get('scene')
  return SCENES.includes(scene as SceneName) ? (scene as SceneName) : null
}

/** Fixture mode is dev-only: never fetched, never bundled, in a real build. */
function fixtureScene(): SceneName | null {
  if (!import.meta.env.DEV) return null
  return sceneFromLocation()
}

/** True when the page is answering from a fixture rather than a server.
 * The one thing outside this file that must know is App.svelte's event
 * stream: a fixture has no server to stream from, and an EventSource
 * opened anyway 502s through vite's proxy and logs a console error --
 * which the pixel gates treat as a failure. */
export function inFixtureMode(): boolean {
  return fixtureScene() !== null
}

// gauntlet's Protect gates (v0.4.2 docs/api/auth.yaml): a signed-in
// session that must finish a step first is refused 403 with the gate
// named in the X-Auth-Gate header and in the problem type's fragment.
const GATES = ['must-change-password', 'must-enrol-factor', 'must-enrol-passkey']

/** True when a 403 is one of gauntlet's Protect gates rather than a
 * plain refusal. Reads the body only when the header does not say. */
async function isGate(res: Response): Promise<boolean> {
  if (GATES.includes(res.headers.get('X-Auth-Gate') ?? '')) return true
  try {
    const body = (await res.json()) as { type?: unknown }
    const type = typeof body?.type === 'string' ? body.type : ''
    return GATES.some((g) => type.endsWith(`errors.md#${g}`))
  } catch {
    return false
  }
}

/** GET a JSON read. A 401, or a 403 from one of gauntlet's gates, also
 * calls the onSignedOut handler (the session has ended, or the door has
 * a step to show), then throws as every other failure does. */
export async function getJSON<T = any>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) {
    if (res.status === 401 || (res.status === 403 && (await isGate(res)))) signedOutHandler()
    throw new ApiError(`${path}: ${res.status}`, res.status)
  }
  return (await res.json()) as T
}

export async function fetchCanaries(range: Range = '14d'): Promise<CanariesResponse> {
  const scene = fixtureScene()
  if (scene) return (await loadFixture(scene)).canaries
  return getJSON<CanariesResponse>(`/api/canaries?range=${range}`)
}

export async function fetchVisitors(range: Range = '14d'): Promise<VisitorsResponse> {
  const scene = fixtureScene()
  if (scene) return (await loadFixture(scene)).visitors
  return getJSON<VisitorsResponse>(`/api/visitors?range=${range}`)
}

export async function fetchTrace(range: Range = '14d'): Promise<TraceResponse> {
  const scene = fixtureScene()
  if (scene) return (await loadFixture(scene)).trace
  return getJSON<TraceResponse>(`/api/trace?range=${range}`)
}

/** GET /api/history (issue #56), optionally narrowed to one canary. Takes
 * the dashboard's own Range straight through -- the endpoint used to
 * keep a separate, smaller set of windows, which let the range picker
 * and the history section disagree about what was on screen (issue #56
 * follow-up). A scene fixture without a history block answers as a
 * fleet with nothing recorded yet rather than failing the section. */
export async function fetchHistory(range: Range = '14d', canary?: string): Promise<HistoryResponse> {
  const scene = fixtureScene()
  if (scene) {
    const fixture = await loadFixture(scene)
    return fixture.history ?? { range, since: fixture.trace.now, until: fixture.trace.now, periods: [], summary: [] }
  }
  const canaryParam = canary ? `&canary=${encodeURIComponent(canary)}` : ''
  return getJSON<HistoryResponse>(`/api/history?range=${range}${canaryParam}`)
}

/** GET /api/mail (issue #55). Range-free, unlike every other read here:
 * "is the thing that wakes me up working" is not a question about a
 * window. A scene fixture without a mail block answers as an instance
 * with mail switched off. */
export async function fetchMail(): Promise<MailStatus> {
  const scene = fixtureScene()
  if (scene) {
    const fixture = await loadFixture(scene)
    return (
      fixture.mail ?? {
        configured: false,
        last_sent_at: null,
        failing_since: null,
        last_error: null,
        pending: 0,
        suppressed: 0,
      }
    )
  }
  return getJSON<MailStatus>('/api/mail')
}

/** GET /api/canary (issue #118): one canary's own page -- the canary as
 * the fleet read already reports it, its standing facts, and every
 * self-test run in the window. A fixture scene without a `canary` block,
 * or without this canary in it, throws the same ApiError a real 404
 * would, so the page draws its not-found line either way. */
export async function fetchCanary(id: string, range: Range = '14d'): Promise<CanaryPageResponse> {
  const scene = fixtureScene()
  if (scene) {
    const page = (await loadFixture(scene)).canary?.[id]
    if (!page) throw new ApiError(`/api/canary?id=${id}: 404`, 404)
    return page
  }
  return getJSON<CanaryPageResponse>(`/api/canary?id=${encodeURIComponent(id)}&range=${range}`)
}

/** GET /api/canaries/{id}/runs (ADR-0012 decision 11): a scanner's own
 * scan-run history -- proof and manual, newest first. A fixture scene
 * without a `runs` block, or without this canary in it, answers as a
 * canary with no run history rather than failing the section: every
 * existing scene predates this endpoint. */
export async function fetchCanaryRuns(id: string): Promise<RunsResponse> {
  const scene = fixtureScene()
  if (scene) {
    const runs = (await loadFixture(scene)).runs?.[id]
    return runs ?? { runs: [] }
  }
  return getJSON<RunsResponse>(`/api/canaries/${encodeURIComponent(id)}/runs`)
}
