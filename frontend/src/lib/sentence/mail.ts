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
  /** Hover text only. The strip has no room for a reason beside the
   *  token-conflict item, so the failure detail lives here, not in text. */
  detail?: string
}

function secondsBetween(from: string, now: string): number {
  return Math.max(0, Math.floor((new Date(now).getTime() - new Date(from).getTime()) / 1000))
}

/** The hover text behind "mail failing since 3 h": the whole SMTP
 * error, flattened to one line. It is not in the strip text itself --
 * beside a token-conflict item the row has no room and it truncated to
 * an ellipsis, which told the operator nothing.
 *
 * The text comes from an SMTP server, so it is not birdcage's own
 * string. Svelte escapes it in the title attribute like every other
 * value the API returns (SECURITY.md, "Output escaping"). */
export function shortReason(lastError: string | null): string {
  if (!lastError) return 'no reason given'
  const flat = lastError.replace(/\s+/g, ' ').trim()
  return flat === '' ? 'no reason given' : flat
}

export function mailLine(mail: MailStatus | null, now: string): MailLine | null {
  if (!mail) return null
  if (!mail.configured) return { text: 'mail off', cls: 'dim' }
  if (mail.failing_since) {
    return {
      text: `mail failing since ${durationCoarse(secondsBetween(mail.failing_since, now))}`,
      cls: 'crit',
      detail: shortReason(mail.last_error),
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
