// The door's shared wording (docs/design/sign-in-screens.md; the text is
// exact) and the helpers every screen uses to turn a refusal into it.
import { ApiError } from '../lib/api'

export const TOO_MANY = 'Too many attempts. Try again later.'
const SSO_STILL_WORKS = 'SSO sign-in still works.'
export const FAILED = 'Sign-in failed. Try again.'
export const ENTER_ACCOUNT = 'Enter your account name.'
export const ENTER_PASSWORD = 'Enter your password.'
export const CONFIRM_PASSWORD = 'Type the password a second time to confirm it.'
export const MISMATCH = 'Passwords do not match.'
export const ENTER_APP_CODE = 'Enter the code from your app.'
export const ENTER_RECOVERY_CODE = 'Enter a recovery code.'
export const INCORRECT_CODE = 'Incorrect code.'
export const INCORRECT_PASSWORD = 'Incorrect password.'
export const TIMED_OUT = 'Your sign-in timed out. Enter your password again.'
/** passkeys/register/finish, 400: the browser's credential (or the
 * name) was refused; the ceremony stays open for another try. */
export const PASSKEY_REFUSED = 'The passkey was not accepted. Try again.'
/** passkeys/register/begin and totp/enrol, 409: a key set up earlier in the last ten
 * minutes is on hold until its recovery codes are confirmed. */
export const PASSKEY_BUSY = 'Another key is waiting for its codes to be saved. Try again in ten minutes.'

/** totp/confirm, 401 step-expired: the pending secret ran out and a new one is shown. */
export const SETUP_TIMED_OUT = 'Set-up timed out: the entry you scanned no longer works. Scan this new code.'
/** Choose screen, an account that needs a passkey where none can be made. */
export const PASSKEY_ONLY_STUCK = 'This account needs a passkey, and none can be made at this address.'
export const SIGN_IN_AS_SOMEONE_ELSE = 'Sign in as someone else'
const PASSKEY_READY = 'Fingerprint, face or device PIN.'
/** The passkey key's line when passkeys are not ready, by passkeys.status. */
const PASSKEY_UNAVAILABLE: Record<string, string> = {
  unset: 'No public address is set. Passkeys need one.',
  ip: 'The public address is an IP. Passkeys need a domain name.',
  insecure: 'The public address is http. Passkeys need https.',
}
const PASSKEY_UNAVAILABLE_OTHER = 'Passkeys need an https web address.'
export const passkeyLine = (status: string | undefined) =>
  status === 'ready' ? PASSKEY_READY : (status !== undefined && Object.hasOwn(PASSKEY_UNAVAILABLE, status) ? PASSKEY_UNAVAILABLE[status] : PASSKEY_UNAVAILABLE_OTHER)

/** A message line: `text`, with `aside` beneath it in the softer ink. */
export interface Message {
  text: string
  aside?: string
}

/** The problem class of a failure, or '' (a network failure, a non-problem body). */
export const kindOf = (err: unknown) => (err instanceof ApiError ? err.kind : '')
export const statusOf = (err: unknown) => (err instanceof ApiError ? err.status : 0)
/** The server's detail, for the two places the specification shows it. */
export const detailOf = (err: unknown) => (err instanceof ApiError ? err.detail : '')

/** 429's line, with the SSO aside when SSO is configured. */
export const tooMany = (sso: boolean): Message => (sso ? { text: TOO_MANY, aside: SSO_STILL_WORKS } : { text: TOO_MANY })
