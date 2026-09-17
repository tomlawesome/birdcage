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
import type { CanariesResponse, Range, TraceResponse, VisitorsResponse } from './types'

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
}

type SceneName = 'quiet' | 'silent' | 'night' | 'alerts'

const SCENES: SceneName[] = ['quiet', 'silent', 'night', 'alerts']

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
