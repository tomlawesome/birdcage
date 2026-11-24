// #227: the admin writes on a canary -- queue a self-test, set or end
// maintenance. One place for the routes and the operator-facing error
// words, so the canary page, the tiles and the events rows say the same
// thing. Every request goes through sendJSON (CSRF header, and a 401
// reaches the sign-in door through its handler).
import { ApiError, sendJSON } from './api'

export type AdminWrite = 'selftest' | 'maintenance-set' | 'maintenance-end'

export const MAINTENANCE_SET_LABEL = 'mark as maintenance · 24 h'
export const MAINTENANCE_END_LABEL = 'end maintenance ▸'

const FAILED: Record<AdminWrite, string> = {
  selftest: 'Could not queue the self-test. Try again.',
  'maintenance-set': 'Could not set maintenance. Try again.',
  'maintenance-end': 'Could not end maintenance. Try again.',
}

/** Sends the write. The PUT carries no body: the 24 h default is the
 * server's. Rejects with the ApiError sendJSON throws. */
export async function sendAdminWrite(kind: AdminWrite, canaryId: string): Promise<void> {
  const base = `/api/admin/canaries/${encodeURIComponent(canaryId)}`
  if (kind === 'selftest') await sendJSON('POST', `${base}/self-test`)
  else await sendJSON(kind === 'maintenance-set' ? 'PUT' : 'DELETE', `${base}/maintenance`)
}

/** What the operator reads when a write fails. The problem document's
 * own detail is never shown. */
export function writeErrorText(kind: AdminWrite, err: unknown): string {
  if (err instanceof ApiError && err.status === 403) return 'Not allowed with this account.'
  return FAILED[kind]
}
