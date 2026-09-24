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

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
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

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) {
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
