// The dashboard's one loader (issue #39): App.svelte fetches the three
// reads together and hands this module the outcome; this module is the
// pure state machine that decides what the page shows, so it's testable
// without a component, a fetch mock, or a timer. App.svelte owns the
// actual fetching, the 30 s interval and the in-flight guard -- none of
// that belongs in a pure reducer.
import type { Canary, TraceResponse, Visitor } from './types'

export interface LoaderData {
  canaries: Canary[]
  visitors: Visitor[]
  trace: TraceResponse
}

// 'loading': nothing has ever loaded yet, a fetch is the only thing that
// can move this state forward.
// 'error': the *first* fetch failed -- there is no data to fall back to,
// so the page shows only the error line.
// 'ready': the last fetch (first or a refetch) succeeded; data is current.
// 'stale': at least one fetch has succeeded, but the most recent one
// failed -- the page keeps showing the last good data, with only the
// footer slot saying the cage stopped answering.
export type LoaderPhase = 'loading' | 'error' | 'ready' | 'stale'

export interface LoaderState {
  phase: LoaderPhase
  data: LoaderData | null
}

export const initialLoaderState: LoaderState = { phase: 'loading', data: null }

/** A fetch (first load or refetch) came back with data. */
export function onFetchSuccess(data: LoaderData): LoaderState {
  return { phase: 'ready', data }
}

/** A fetch (first load or refetch) failed. Falls back to 'error' only
 * when there is no earlier good data to keep showing -- otherwise the
 * existing data stays put and only the phase moves to 'stale'. */
export function onFetchError(state: LoaderState): LoaderState {
  if (state.data) return { phase: 'stale', data: state.data }
  return { phase: 'error', data: null }
}
