// Issue #55's one item in the top status strip: whether the thing that
// is supposed to wake the operator up is working.
//
// It is deliberately three short states and no more. The strip is a row
// of terse facts about the fleet ("3 of 4 phoning home", "◎ 12
// visitors"), not a place to explain a mail configuration -- an
// operator who wants detail opens their configuration, and everything
// GET /api/mail knows is there for a later settings view to use.
//
// "mail off" is not a warning. Running birdcage without outbound mail
// is a perfectly ordinary choice, so it reads muted, like the rest of
// the strip. "mail failing" is the alarm class, because a mailer that
// has silently stopped working is the failure this feature is most
// exposed to: nothing else on the dashboard would go red about it.
import type { MailStatus } from '../types'
import { durationCoarse } from './duration'

export interface MailLine {
  text: string
  /** An existing status-strip class: 'dim' muted, 'crit' the alarm. */
  cls: 'dim' | 'crit'
}

/** How much of an SMTP error the strip will carry. Short because this
 * sits in a fixed-width row beside the rest of the status, and because
 * the whole error is on GET /api/mail for anything that wants it. */
const MAX_REASON = 32

function secondsBetween(from: string, now: string): number {
  return Math.max(0, Math.floor((new Date(now).getTime() - new Date(from).getTime()) / 1000))
}

/** The tail of "mail failing since 3 h — <short reason>": one line, no
 * longer than MAX_REASON, cut at a word boundary where there is one.
 *
 * The text comes from an SMTP server, so it is not birdcage's own
 * string. Svelte's text interpolation escapes it at render like every
 * other value the API returns (SECURITY.md, "Output escaping"); the
 * only thing done here is flattening line breaks, which would otherwise
 * break the strip's layout rather than anything worse. */
export function shortReason(lastError: string | null): string {
  if (!lastError) return 'no reason given'
  const flat = lastError.replace(/\s+/g, ' ').trim()
  if (flat === '') return 'no reason given'
  if (flat.length <= MAX_REASON) return flat
  const cut = flat.slice(0, MAX_REASON)
  const lastSpace = cut.lastIndexOf(' ')
  return `${(lastSpace > MAX_REASON / 2 ? cut.slice(0, lastSpace) : cut).trimEnd()}…`
}

/** The strip's mail item, or null before the first /api/mail response
 * has landed -- the strip simply has one fewer item until then, rather
 * than claiming a state it does not know yet. */
export function mailLine(mail: MailStatus | null, now: string): MailLine | null {
  if (!mail) return null
  if (!mail.configured) return { text: 'mail off', cls: 'dim' }
  if (mail.failing_since) {
    return {
      text: `mail failing since ${durationCoarse(secondsBetween(mail.failing_since, now))} — ${shortReason(mail.last_error)}`,
      cls: 'crit',
    }
  }
  if (mail.last_sent_at) {
    return { text: `mail ok · last ${durationCoarse(secondsBetween(mail.last_sent_at, now))} ago`, cls: 'dim' }
  }
  // Configured, nothing has ever failed, nothing has ever been sent --
  // the ordinary state of a fleet that has never had a token conflict,
  // which is what most of them should look like forever.
  return { text: 'mail ok · nothing sent yet', cls: 'dim' }
}
