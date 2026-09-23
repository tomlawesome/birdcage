// The facts column (ADR-0004 rule 5): the standing facts about one
// canary, as label/value rows. Every value comes from GET /api/canary's
// `facts` block or the canary itself -- nothing is inferred, and a fact
// birdcage does not know is left out rather than guessed at.
import { intervalWords } from './sentence'
import { canaryOf, selfTestCards, type CanaryPageInput } from './model'

export interface FactRow {
  label: string
  value: string
  /** Rendered in the canary's lane colour, as its name is everywhere
   * else on the page. */
  accent?: boolean
}

const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']

function stamp(iso: string, withClock: boolean): string {
  const d = new Date(iso)
  const date = `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`
  if (!withClock) return date
  const hh = String(d.getUTCHours()).padStart(2, '0')
  const mm = String(d.getUTCMinutes()).padStart(2, '0')
  return `${date} ${hh}:${mm}`
}

/** "25 h" / "3 d" -- a countdown, not a duration: hours stay hours up to
 * two days, because "next in 25 h" answers "is it tonight?" where
 * durationCoarse's "1 d" does not. */
function countdown(seconds: number): string {
  const hours = Math.round(seconds / 3600)
  if (hours < 48) return `${hours} h`
  return `${Math.round(hours / 24)} d`
}

export function factRows(input: CanaryPageInput): FactRow[] {
  const canary = canaryOf(input)
  const facts = input.page.facts
  const now = Date.parse(input.trace.now)
  const rows: FactRow[] = [{ label: 'kind', value: facts.kind }]

  rows.push({ label: 'lane', value: canary.lane, accent: true })
  if (facts.address) rows.push({ label: 'address', value: facts.address })
  if (facts.ports) rows.push({ label: 'listening', value: facts.ports })

  const lures = selfTestCards(canary)
    .filter((card) => card.lure)
    .map((card) => card.service)
  if (lures.length > 0) rows.push({ label: 'lure only', value: lures.join(' · ') })

  rows.push({ label: 'heartbeat', value: `every ${intervalWords(facts.heartbeat_interval_s)}` })
  rows.push({
    label: 'self-test',
    value: facts.self_test_enabled ? `daily · ${facts.self_test_schedule}` : 'off',
  })
  rows.push({ label: 'enrolled', value: stamp(facts.enrolled_at, true) })
  if (facts.agent_version) rows.push({ label: 'agent', value: `mockingbird ${facts.agent_version}` })

  if (facts.token_rotated_at) {
    const next = facts.token_rotates_at ? Date.parse(facts.token_rotates_at) : null
    const nextClause = next !== null && next > now ? ` · next in ${countdown((next - now) / 1000)}` : ''
    rows.push({ label: 'token', value: `rotated ${stamp(facts.token_rotated_at, false)}${nextClause}` })
  }
  return rows
}
