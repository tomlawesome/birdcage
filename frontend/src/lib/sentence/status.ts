// The top-right status pill (issue #38): "● LIVE · 4 canaries", "⚑ 1",
// "◎ 4 visitors"; silent: "○ 3 of 4 phoning home · canary-iot silent 6 m".
import type { Canary, Range, Visitor } from '../types'
import { durationMinutesOnly } from './duration'

export type StatusInfo =
  | { kind: 'quiet'; okCount: number; total: number; visitorCount: number; range: Range }
  | {
      kind: 'silent'
      okCount: number
      total: number
      visitorCount: number
      range: Range
      silentName: string
      silentFor: string
    }
  | { kind: 'live'; total: number; visitorCount: number; flagCount: number }

export function computeStatus(canaries: Canary[], visitors: Visitor[], range: Range): StatusInfo {
  const okCount = canaries.filter((c) => c.status === 'ok').length
  const total = canaries.length
  const visitorCount = visitors.length
  const silent = canaries.find((c) => c.status === 'silent')

  if (silent) {
    return {
      kind: 'silent',
      okCount,
      total,
      visitorCount,
      range,
      silentName: silent.name,
      silentFor: durationMinutesOnly(silent.silent_for_s ?? 0),
    }
  }
  if (visitorCount > 0) {
    const flagCount = visitors.filter((v) => v.kind === 'sweep' && v.still_arriving).length
    return { kind: 'live', total, visitorCount, flagCount }
  }
  return { kind: 'quiet', okCount, total, visitorCount, range }
}
