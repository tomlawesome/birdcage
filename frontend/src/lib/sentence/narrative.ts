import type { Range } from '../types'
import { wordOrNumber } from './words'

/** "all four canaries" when every canary was touched, else "n canaries"
 * (gen.py NIGHT_SUB: "has reached all four canaries in nine minutes"). */
export function canariesPhrase(touched: number, total: number): string {
  if (touched === total && total > 0) return `all ${wordOrNumber(total)} canaries`
  return `${wordOrNumber(touched)} ${touched === 1 ? 'canary' : 'canaries'}`
}

/** "nine minutes" (gen.py NIGHT_SUB). */
export function minutesPhrase(minutes: number): string {
  return `${wordOrNumber(minutes)} ${minutes === 1 ? 'minute' : 'minutes'}`
}

/** The services a visitor walked, narrated as "svc, then svc" (gen.py
 * NIGHT_SUB: "ssh, then mysql" -- the sweep also touched telnet, but the
 * concept names only the first two services it reached). */
export function servicesNarrative(services: string[]): string {
  if (services.length === 0) return ''
  if (services.length === 1) return services[0]
  return `${services[0]}, then ${services[1]}`
}

const WEAK_CRED_RE = /root|admin|toor|password|123456|\(empty\)/i

/** "default passwords" when the tried credentials look like common weak
 * defaults (gen.py NIGHT_SUB's other half of "ssh, then mysql, default
 * passwords"), else the tried values themselves. */
export function triedNarrative(tried: string[]): string {
  if (tried.length === 0) return ''
  const weak = tried.filter((t) => WEAK_CRED_RE.test(t)).length
  if (weak >= Math.ceil(tried.length / 2)) return 'default passwords'
  return [...new Set(tried)].join(', ')
}

const RANGE_NOUN: Record<Range, string> = {
  '15m': 'quarter hour',
  '1h': 'hour',
  '24h': 'day',
  '14d': 'fortnight',
  '90d': '90 days',
}

/** "the fortnight" (gen.py NIGHT_SUB: "Three more visitors in the fortnight."). */
export function rangeNoun(range: Range): string {
  return RANGE_NOUN[range]
}

const RANGE_LONG: Record<Range, string> = {
  '15m': '15 minutes',
  '1h': '1 hour',
  '24h': '24 hours',
  '14d': '14 days',
  '90d': '90 days',
}

/** "14 days" -- the events heading's range label (gen.py: "events · 14 days · none"). */
export function rangeLong(range: Range): string {
  return RANGE_LONG[range]
}
