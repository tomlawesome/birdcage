import { describe, expect, it } from 'vitest'
import type { MailStatus } from '../types'
import { mailLine, shortReason } from './mail'

const NOW = '2026-09-17T09:00:00Z'

function status(overrides: Partial<MailStatus> = {}): MailStatus {
  return {
    configured: true,
    last_sent_at: null,
    failing_since: null,
    last_error: null,
    pending: 0,
    suppressed: 0,
    ...overrides,
  }
}

describe('the status strip mail item (#55)', () => {
  it('says mail is off, muted, when nothing is configured', () => {
    expect(mailLine(status({ configured: false }), NOW)).toEqual({ text: 'mail off', cls: 'dim' })
  })

  it('says how long ago the last message went, muted', () => {
    // 07:00 against the 09:00 clock.
    const line = mailLine(status({ last_sent_at: '2026-09-17T07:00:00Z' }), NOW)
    expect(line).toEqual({ text: 'mail ok · last 2 h ago', cls: 'dim' })
  })

  it('says how long mail has been failing, in the alarm class', () => {
    // 06:00 against the 09:00 clock.
    const line = mailLine(
      status({
        last_sent_at: '2026-09-16T21:00:00Z',
        failing_since: '2026-09-17T06:00:00Z',
        last_error: 'could not send the token_conflict alert: TLS connect to smtp.example.net:465: connection refused',
      }),
      NOW,
    )
    expect(line).toEqual({
      text: 'mail failing since 3 h',
      cls: 'crit',
      detail: 'could not send the token_conflict alert: TLS connect to smtp.example.net:465: connection refused',
    })
  })

  it('draws nothing until the first response lands', () => {
    expect(mailLine(null, NOW)).toBeNull()
  })

  it('reads sensibly for a fleet that has never had anything to report', () => {
    expect(mailLine(status(), NOW)).toEqual({ text: 'mail ok · nothing sent yet', cls: 'dim' })
  })

  // Failing wins over a successful send: the useful fact is that mail
  // has stopped working, not that it worked yesterday.
  it('reports failure even when something was sent earlier', () => {
    const line = mailLine(
      status({ last_sent_at: '2026-09-17T08:00:00Z', failing_since: '2026-09-17T08:30:00Z', last_error: 'nope' }),
      NOW,
    )
    expect(line?.cls).toBe('crit')
    expect(line?.text).toBe('mail failing since 30 m')
    expect(line?.detail).toBe('nope')
  })
})

describe('shortReason', () => {
  it('passes a short reason through', () => {
    expect(shortReason('connection refused')).toBe('connection refused')
  })

  it('flattens line breaks so the hover reads as one line', () => {
    expect(shortReason('two\nlines  here')).toBe('two lines here')
  })

  it('has something to say when the server gave no reason', () => {
    expect(shortReason(null)).toBe('no reason given')
    expect(shortReason('   ')).toBe('no reason given')
  })
})
