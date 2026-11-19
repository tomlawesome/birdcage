// Sign-in state (issue #8, ADR-0016 and ADR-0017): what gauntlet's
// GET /api/auth/session reports, and which screen of the door it names.
// The wire shapes are gauntlet v0.4.2's (docs/api/auth.yaml in that
// module); docs/design/sign-in-screens.md is the specification.
import { getJSON, inFixtureMode } from './api'

export type PasskeyStatus = 'ready' | 'unset' | 'ip' | 'insecure'

export interface SessionState {
  setupRequired: boolean
  ssoAvailable: boolean
  authenticated: boolean
  hasLocalPassword: boolean
  ssoConnected: boolean
  mustChangePassword: boolean
  mustEnrolSecondFactor: boolean
  mustEnrolPasskey: boolean
  hasTOTP: boolean
  /** Present only while authenticated. */
  username?: string
  role?: string
  passkeys?: { count?: number; status: PasskeyStatus | string; origin?: string; signIn?: boolean }
  /** Present, as true, only while signed out with a session that timed
   * out and can be resumed with the password. */
  resumable?: boolean
}

export type Door = 'firstrun' | 'newpassword' | 'choose' | 'in' | 'expired' | 'signin'

/** Which screen the session names. First match wins. */
export function doorFor(s: SessionState): Door {
  if (s.setupRequired) return 'firstrun'
  if (s.authenticated && s.mustChangePassword) return 'newpassword'
  if (s.authenticated && (s.mustEnrolSecondFactor || s.mustEnrolPasskey)) return 'choose'
  if (s.authenticated) return 'in'
  if (s.resumable) return 'expired'
  return 'signin'
}

// A dev-only fixture scene (`?scene=`, see lib/api.ts) has no server to
// sign in to: it answers as a signed-in admin, so the dashboard's pixel
// gates draw the shell as they always have.
const FIXTURE_SESSION: SessionState = {
  setupRequired: false,
  ssoAvailable: false,
  authenticated: true,
  hasLocalPassword: true,
  ssoConnected: false,
  mustChangePassword: false,
  mustEnrolSecondFactor: false,
  mustEnrolPasskey: false,
  hasTOTP: true,
  username: 'avery',
  role: 'admin',
}

/** GET /api/auth/session. */
export async function readSession(): Promise<SessionState> {
  if (inFixtureMode()) return { ...FIXTURE_SESSION }
  return getJSON<SessionState>('/api/auth/session')
}

/** A login or second-factor reply: an account, a second factor to ask
 * for, a passkey owed (`prove`), or a confirmation code sent (#189, not
 * built). */
export type LoginReply =
  | { kind: 'account'; username: string; role: string }
  | { kind: 'secondFactor'; methods: string[] }
  | { kind: 'prove' }
  | { kind: 'other' }

export function readLoginReply(body: unknown): LoginReply {
  const b = (body ?? {}) as Record<string, unknown>
  if (Array.isArray(b.secondFactor)) return { kind: 'secondFactor', methods: b.secondFactor.filter((m): m is string => typeof m === 'string') }
  if (b.prove === 'passkey') return { kind: 'prove' }
  if (typeof b.username === 'string' && typeof b.role === 'string') return { kind: 'account', username: b.username, role: b.role }
  return { kind: 'other' }
}
