// The facts column (ADR-0004 rule 5): the standing facts about one
// canary, as label/value rows. Every value comes from GET /api/canary's
// `facts` block or the canary itself -- nothing is inferred, and a fact
// birdcage does not know is left out rather than guessed at.
import { intervalWords } from './sentence'
import { canaryOf, selfTestCards, type CanaryPageInput } from './model'
import { shortVersion } from '../sentence/version'

export interface FactRow {
  label: string
  value: string
  /** Rendered in the canary's lane colour, as its name is everywhere
   * else on the page. */
  accent?: boolean
  /** Issue #54: present only for the upgrade-command row -- rendered
   * as a copyable code block instead of plain text, `value` left empty. */
  code?: string
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

  // The bait names the poisoner detector is asking for (#86 slice D).
  // Shown with the separator every other multi-value row here uses, so a
  // reader can see at a glance how many there are.
  //
  // This screen is the only place these appear. The canary keeps them out
  // of every log line on purpose -- the bait only works while nobody knows
  // which names it uses, and a honeypot's stdout is readable by whoever
  // breaks into it -- so an operator who wants to know what their canaries
  // are baiting with reads it here.
  if (facts.poisoner_names) {
    rows.push({ label: 'bait names', value: facts.poisoner_names.split(',').join(' · ') })
  }

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

  // Issue #54: birdcage's own comparison of the agent's build against
  // its own stamped version -- a standing fact, shown whenever
  // agent_out_of_date is active, whether or not it is the state
  // currently ranked worst on `status` (a worse fault, e.g. 'silent',
  // can hold `status` while the canary is still behind underneath it --
  // `active_states` is what says so). The backend is the single source
  // of truth for "behind": the frontend never re-derives it by comparing
  // version strings itself. `upgrade_command` is the multi-line script
  // an operator pastes on the box; an active backend that sent none yet
  // points at the docs instead of a dangling row.
  const behind = canary.status === 'agent_out_of_date' || (canary.active_states?.includes('agent_out_of_date') ?? false)
  if (behind) {
    rows.push({
      label: 'upgrade',
      value: `runs ${shortVersion(facts.agent_version ?? '?')} · current ${shortVersion(canary.birdcage_version ?? '?')}`,
    })
    rows.push(
      canary.upgrade_command
        ? { label: 'run this', value: '', code: canary.upgrade_command }
        : {
            label: 'run this',
            value: 'not available yet — see docs/enrolment.md, "Upgrading a canary"',
          },
    )
  }

  if (facts.token_rotated_at) {
    const next = facts.token_rotates_at ? Date.parse(facts.token_rotates_at) : null
    const nextClause = next !== null && next > now ? ` · next in ${countdown((next - now) / 1000)}` : ''
    rows.push({ label: 'token', value: `rotated ${stamp(facts.token_rotated_at, false)}${nextClause}` })
  }

  // Issue #124's per-canary settings: one row per canary_settings row,
  // value plus whether the agent has confirmed it -- the same "● / ○
  // word" convention ledger.ts's answerWords already uses for a
  // self-test service's own answered/did-not-answer state, so this reads
  // as the same kind of fact rather than a new visual language. Absent
  // entirely for a canary nothing has ever been pushed to, matching this
  // whole column's "a fact birdcage does not know is left out" rule.
  for (const setting of facts.settings ?? []) {
    const mark = setting.confirmed ? '● confirmed' : '○ not yet confirmed'
    rows.push({ label: setting.key.replace(/_/g, ' '), value: `${setting.value} · ${mark}` })
  }
  return rows
}
