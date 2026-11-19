// Spec: docs/design/sign-in-screens.md, "Add a second step" and "Set a
// new password" (issue #210): the way out of held screens, the passkey
// key's status lines, an expired and a held authenticator set-up.
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Door from './Door.svelte'
import { flush, jsonReply, problem, session, stubBrowser, stubCredentials, stubServer } from './testkit'

beforeEach(() => stubBrowser())
afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  localStorage.clear()
  sessionStorage.clear()
})

const type = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } })
const ph = (t: string) => screen.getByPlaceholderText(t) as HTMLInputElement
const btn = (name: string) => screen.getByRole('button', { name })
const OUT = 'Sign in as someone else'
const BUSY = 'Another key is waiting for its codes to be saved. Try again in ten minutes.'
const TIMED_OUT = 'Set-up timed out: the entry you scanned no longer works. Scan this new code.'
const ENROL = { uri: 'otpauth://totp/birdcage:ana?secret=AAAAAAAAAAAAAAAA', secret: 'AAAAAAAAAAAAAAAA' }
const NEW_ENROL = { uri: 'otpauth://totp/birdcage:ana?secret=BBBBBBBBBBBBBBBB', secret: 'BBBBBBBBBBBBBBBB' }

const owed = (over: Record<string, unknown> = {}) =>
  session({ authenticated: true, mustEnrolSecondFactor: true, passkeys: { count: 0, status: 'ready' }, ...over })

function server(extra: Record<string, any> = {}) {
  return stubServer({ 'POST /api/auth/logout': jsonReply({}), 'GET /api/auth/session': jsonReply(session()), ...extra })
}

async function signedOutFirst(s: ReturnType<typeof server>) {
  await fireEvent.click(screen.getByText(OUT))
  expect(await screen.findByPlaceholderText('account')).toBeTruthy()
  const out = s.to('POST', '/api/auth/logout')
  expect(out).toHaveLength(1)
  expect(out[0].headers['x-requested-with']).toBe('birdcage')
}

async function toTotpProve() {
  await fireEvent.click(screen.getByText('Authenticator app'))
  await type(ph('password'), 'pw-fake-1')
  await fireEvent.click(btn('Continue'))
  await screen.findByPlaceholderText('6-digit code')
}

describe('Sign in as someone else on the held screens', () => {
  it('choose screen: link present; click logs out and shows sign in', async () => {
    const s = server()
    render(Door, { session: owed(), onenter: () => {} })
    await signedOutFirst(s)
  })

  it('password screen: link present; click logs out and shows sign in', async () => {
    const s = server()
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await screen.findByPlaceholderText('password')
    await signedOutFirst(s)
  })

  it('prove (authenticator) screen: link present; click logs out and shows sign in', async () => {
    const s = server({ 'POST /api/auth/totp/enrol': jsonReply(ENROL) })
    render(Door, { session: owed(), onenter: () => {} })
    await toTotpProve()
    await signedOutFirst(s)
  })

  it('prove (passkey) screen: link present; click logs out and shows sign in', async () => {
    const s = server()
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Passkey'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await screen.findByPlaceholderText('name')
    await signedOutFirst(s)
  })

  it('new-password screen: link present; click logs out and shows sign in', async () => {
    const s = server()
    render(Door, { session: session({ authenticated: true, mustChangePassword: true }), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Set a new password' })).toBeTruthy()
    await signedOutFirst(s)
  })

  it('the link comes after the "instead" link on the prove screens', async () => {
    server({ 'POST /api/auth/totp/enrol': jsonReply(ENROL) })
    render(Door, { session: owed(), onenter: () => {} })
    await toTotpProve()
    const instead = screen.getByText('Use a passkey instead')
    const out = screen.getByText(OUT)
    expect(instead.compareDocumentPosition(out) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('recovery-codes screen: no such link', async () => {
    server({
      'POST /api/auth/totp/enrol': jsonReply(ENROL),
      'POST /api/auth/totp/confirm': jsonReply({ recoveryCodes: ['c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10'] }),
    })
    render(Door, { session: owed(), onenter: () => {} })
    await toTotpProve()
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await screen.findByRole('heading', { name: 'Keep the codes' })
    expect(screen.queryByText(OUT)).toBeNull()
  })
})

describe('passkey-only account with passkeys not ready', () => {
  const stuck = (status: string) => owed({ mustEnrolPasskey: true, passkeys: { count: 0, status } })

  it('shows the alert', () => {
    server()
    render(Door, { session: stuck('insecure'), onenter: () => {} })
    expect(screen.getByRole('alert').textContent).toBe('This account needs a passkey, and none can be made at this address.')
  })

  it('no alert when the passkey is ready', () => {
    server()
    render(Door, { session: stuck('ready'), onenter: () => {} })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('no alert when the authenticator app is also offered', () => {
    server()
    render(Door, { session: owed({ passkeys: { count: 0, status: 'insecure' } }), onenter: () => {} })
    expect(screen.queryByText(/none can be made at this address/)).toBeNull()
  })

  it('the way out is the link, which signs out', async () => {
    const s = server()
    render(Door, { session: stuck('unset'), onenter: () => {} })
    await signedOutFirst(s)
  })
})

describe('the passkey key status line', () => {
  const lines: [string, string][] = [
    ['unset', 'No public address is set. Passkeys need one.'],
    ['ip', 'The public address is an IP. Passkeys need a domain name.'],
    ['insecure', 'The public address is http. Passkeys need https.'],
    ['something-new', 'Passkeys need an https web address.'],
  ]
  it.each(lines)('%s', (status, line) => {
    server()
    render(Door, { session: owed({ passkeys: { count: 0, status } }), onenter: () => {} })
    const key = screen.getByText('Passkey').closest('button') as HTMLButtonElement
    expect(key.disabled).toBe(true)
    expect(key.textContent).toContain(line)
    expect(key.textContent).not.toContain('Fingerprint, face or device PIN.')
  })

  it('a missing status takes the fallback line', () => {
    server()
    render(Door, { session: owed({ passkeys: { count: 0 } }), onenter: () => {} })
    expect((screen.getByText('Passkey').closest('button') as HTMLElement).textContent).toContain('Passkeys need an https web address.')
  })

  it('ready: enabled with its description', () => {
    server()
    render(Door, { session: owed(), onenter: () => {} })
    const key = screen.getByText('Passkey').closest('button') as HTMLButtonElement
    expect(key.disabled).toBe(false)
    expect(key.textContent).toContain('Fingerprint, face or device PIN.')
  })
})

describe('authenticator set-up that ran out', () => {
  it('step-expired: timed-out message, code cleared, new secret shown', async () => {
    const s = server({
      'POST /api/auth/totp/enrol': [jsonReply(ENROL), jsonReply(NEW_ENROL)],
      'POST /api/auth/totp/confirm': problem('step-expired', 401),
    })
    render(Door, { session: owed(), onenter: () => {} })
    await toTotpProve()
    expect(document.body.textContent?.replace(/\s+/g, '')).toContain('AAAA'.repeat(4))
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await waitFor(() => expect(s.to('POST', '/api/auth/totp/enrol')).toHaveLength(2))
    expect((await screen.findByRole('alert')).textContent).toBe(TIMED_OUT)
    expect(ph('6-digit code').value).toBe('')
    await waitFor(() => expect(document.body.textContent?.replace(/\s+/g, '')).toContain('BBBB'.repeat(4)))
    expect(document.body.textContent?.replace(/\s+/g, '')).not.toContain('AAAA'.repeat(4))
  })
})

describe('totp/enrol 409', () => {
  it('from the choose screen (password held): the busy message, still on choose', async () => {
    // reach choose with a held password: go through a passkey pick first, then back
    server({ 'POST /api/auth/totp/enrol': problem('conflict', 409) })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Passkey'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await screen.findByPlaceholderText('name')
    await fireEvent.click(screen.getByText('Use an authenticator app instead'))
    expect((await screen.findByRole('alert')).textContent).toBe(BUSY)
    expect(screen.queryByPlaceholderText('6-digit code')).toBeNull()
  })

  it('from the password screen: the busy message, still on the password screen', async () => {
    server({ 'POST /api/auth/totp/enrol': problem('conflict', 409) })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    expect((await screen.findByRole('alert')).textContent).toBe(BUSY)
    expect(screen.getByPlaceholderText('password')).toBeTruthy()
  })

  it('on the expired-set-up retry: the busy message, not the timed-out one', async () => {
    server({
      'POST /api/auth/totp/enrol': [jsonReply(ENROL), problem('conflict', 409)],
      'POST /api/auth/totp/confirm': problem('step-expired', 401),
    })
    render(Door, { session: owed(), onenter: () => {} })
    await toTotpProve()
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe(BUSY))
  })
})
void flush
void stubCredentials
