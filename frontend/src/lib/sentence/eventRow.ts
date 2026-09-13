// One row per visitor (issue #38 / gen.py EVENTS_NIGHT, EVENTS_SILENT),
// newest first, plus the quiet-day heading and its one italic line.
// Reads only Canary (for the dropped-out row and the "N of total"
// denominator) and Visitor -- unlike tiles, no hit-level detail is
// needed here, since a visitor's own first_at/last_at/hits already
// describe its row.
import type { Canary, Range, Visitor, VisitorKind } from '../types'
import { formatClock } from './time'
import { calendarDaysBetween, isSameUTCDate, relativeDayLabel } from './time'
import { durationExact } from './duration'
import { canariesPhrase, minutesPhrase, rangeLong, servicesNarrative, triedNarrative } from './narrative'
import { portForService } from './ports'
import { wordOrNumber } from './words'
import type { Segment } from './types'

export interface EventTime {
  primary: string
  small: string
}

export interface EventKind {
  symbol: string
  label: string
  small: string
}

export interface EventAction {
  label: string
  quiet?: boolean
}

export interface EventRow {
  key: string
  cls: string
  time: EventTime
  kind: EventKind
  who: Segment[]
  actions: EventAction[]
}

const KIND_CLS: Record<VisitorKind, string> = { sweep: 'k-sw', repeat: 'k-rp', inside: 'k-in', touch: 'k-tc' }
const KIND_SYMBOL: Record<VisitorKind, string> = { sweep: '✱', repeat: '✱', inside: '✱', touch: '▲' }
const KIND_LABEL: Record<VisitorKind, string> = {
  sweep: 'SWEEP',
  repeat: 'REPEAT',
  inside: 'FROM INSIDE',
  touch: 'ONE TOUCH',
}

/** The newest visitor's `last_at` stands in for "now" -- Events reads only
 * /api/visitors (issue #38), and a still-arriving visitor's last hit is
 * effectively the current time anyway. */
export function deriveNow(visitors: Visitor[]): string | null {
  if (visitors.length === 0) return null
  return visitors.reduce((max, v) => (v.last_at > max ? v.last_at : max), visitors[0].last_at)
}

function elapsedSmall(at: string, now: string): string {
  const ms = Math.max(0, Date.parse(now) - Date.parse(at))
  const hours = Math.round(ms / 3_600_000)
  if (hours >= 1) return `${hours} h ago`
  const minutes = Math.max(1, Math.round(ms / 60_000))
  return `${minutes} m ago`
}

function timeColumn(v: Visitor, now: string): EventTime {
  if (!isSameUTCDate(v.last_at, now)) {
    return { primary: relativeDayLabel(v.last_at, now), small: formatClock(v.last_at) }
  }
  if (v.kind === 'sweep' && v.still_arriving) {
    const minutes = Math.max(0, Math.round((Date.parse(v.last_at) - Date.parse(v.first_at)) / 60_000))
    return { primary: formatClock(v.last_at), small: `${minutes} m · still arriving` }
  }
  if (v.kind === 'repeat') {
    const nights = calendarDaysBetween(v.first_at, v.last_at) + 1
    return { primary: formatClock(v.last_at), small: `${nights} nights · on schedule` }
  }
  return { primary: formatClock(v.last_at), small: elapsedSmall(v.last_at, now) }
}

function defaultActions(v: Visitor): EventAction[] {
  switch (v.kind) {
    case 'sweep':
      return [{ label: 'lookback in mikroview ▸' }, { label: 'raw lines ▸' }]
    case 'repeat':
      return [{ label: 'already blocked', quiet: true }]
    case 'inside':
      return [{ label: 'which device? ▸' }]
    case 'touch':
      return [{ label: 'clear with a note', quiet: true }]
  }
}

function whoSentence(v: Visitor, canaries: Canary[]): Segment[] {
  const total = canaries.length
  const canary = canaries.find((c) => c.id === v.canaries[0]?.id)
  const canaryPort = canary ? `${canary.name} :${portForService(canary.ports, v.services[0]) ?? ''}` : ''

  if (v.kind === 'sweep') {
    const minutes = Math.max(0, Math.round((Date.parse(v.last_at) - Date.parse(v.first_at)) / 60_000))
    const startedToday = isSameUTCDate(v.first_at, v.last_at)
    return [
      { text: v.source_ip, cls: 'ip' },
      { text: ' walked ' },
      { text: `${canariesPhrase(v.canaries.length, total)} in ${minutesPhrase(minutes)}`, bold: true },
      { text: ` — ${servicesNarrative(v.services)}, ${triedNarrative(v.tried)}.` },
      { text: v.still_arriving && startedToday ? ' Never seen before tonight.' : '' },
    ]
  }
  if (v.kind === 'repeat') {
    const spanMinutes = Math.max(1, Math.round((Date.parse(v.last_at) - Date.parse(v.first_at)) / 60_000))
    const interval = Math.max(1, Math.round(spanMinutes / Math.max(1, v.hits - 1)))
    const nights = calendarDaysBetween(v.first_at, v.last_at) + 1
    return [
      { text: v.source_ip, cls: 'ip' },
      { text: ` knocks on ${canaryPort} every ~${interval} minutes through the night, ${wordOrNumber(nights)} nights running.` },
    ]
  }
  if (v.kind === 'inside') {
    const last = v.tried[v.tried.length - 1] ?? ''
    return [
      { text: v.source_ip, cls: 'ip' },
      { text: ` browsed ${canaryPort} and tried ` },
      { text: last, bold: true },
      { text: '.' },
    ]
  }
  const cred = (v.tried[0] ?? '').split(' / ')[0]
  return [
    { text: v.source_ip, cls: 'ip' },
    { text: ` logged in to ${canaryPort} as ${cred}, once, and left.` },
  ]
}

export function computeEventRow(v: Visitor, canaries: Canary[], now: string): EventRow {
  return {
    key: `${v.source_ip}-${v.kind}-${v.last_at}`,
    cls: KIND_CLS[v.kind],
    time: timeColumn(v, now),
    kind: {
      symbol: KIND_SYMBOL[v.kind],
      label: KIND_LABEL[v.kind],
      small: `${v.hits}× · ${v.canaries.length} of ${canaries.length}`,
    },
    who: whoSentence(v, canaries),
    actions: defaultActions(v),
  }
}

export function computeDroppedOutRow(canary: Canary): EventRow {
  return {
    key: `dropped-${canary.id}`,
    cls: 'k-off',
    time: { primary: formatClock(canary.last_heartbeat_at ?? ''), small: `${durationExact(canary.silent_for_s ?? 0)} ago` },
    kind: { symbol: '○', label: 'DROPPED OUT', small: canary.name },
    who: [
      { text: canary.name, bold: true },
      {
        text: ` stopped phoning home. ${capitalize(wordOrNumber(canary.beats_missed ?? 0))} heartbeats missed since. Not a visitor: the host may be down, or its firewall rule on the router may have moved.`,
      },
    ],
    actions: [
      { label: `open ${canary.name} ▸` },
      { label: 'lookback in mikroview ▸' },
      { label: 'mark as maintenance', quiet: true },
    ],
  }
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export interface EventsHeading {
  segments: Segment[]
  showQuietLine: boolean
}

export function computeEventsHeading(canaries: Canary[], visitors: Visitor[], range: Range): EventsHeading {
  const silentCount = canaries.filter((c) => c.status === 'silent').length
  const prefix = `events · ${rangeLong(range)} · `
  if (visitors.length === 0 && silentCount === 0) {
    return { segments: [{ text: prefix }, { text: 'none', bold: true }], showQuietLine: true }
  }
  if (visitors.length === 0) {
    return {
      segments: [{ text: prefix }, { text: String(silentCount), bold: true }, { text: ' · no visitors' }],
      showQuietLine: false,
    }
  }
  return {
    segments: [{ text: prefix }, { text: `${visitors.length} visitors`, bold: true }, { text: ' · newest first' }],
    showQuietLine: false,
  }
}

export const QUIET_LINE =
  'Nothing in the window. A flat trace is the cage working — the only things moving on this page are the heartbeats.'
