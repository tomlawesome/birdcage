// The door's shared wording (docs/design/sign-in-screens.md; the text is
// exact) and the helpers every screen uses to turn a refusal into it.
import { ApiError } from '../lib/api'

export const TOO_MANY = 'Too many attempts. Try again later.'
export const SSO_STILL_WORKS = 'SSO sign-in still works.'
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
/** passkeys/register/begin, 409: a key set up earlier in the last ten
 * minutes is on hold until its recovery codes are confirmed. */
export const PASSKEY_BUSY = 'Another key is waiting for its codes to be saved. Try again in ten minutes.'

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
