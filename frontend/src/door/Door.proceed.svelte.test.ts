// The door stays busy until the session has been read again after a
// step that could finish signing in: a second submit in that time sends
// nothing, and onenter is called once.
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Door from './Door.svelte'
import { accountReply, deferred, flush, jsonReply, problem, session, stubBrowser, stubCredentials, stubServer } from './testkit'

beforeEach(() => stubBrowser())
afterEach(() => vi.unstubAllGlobals())

const type = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } })
const signedIn = () => session({ authenticated: true, username: 'ana', role: 'admin' })

describe('re-reading the session after a step', () => {
  it('sign in: busy until the session is read; a second submit sends nothing; onenter once', async () => {
    const read = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/login': accountReply(), 'GET /api/auth/session': () => read.promise })
    const onenter = vi.fn()
    render(Door, { session: session(), onenter })
    await type(screen.getByPlaceholderText('account'), 'ana')
    await type(screen.getByPlaceholderText('password'), 'pw-fake-1')
    const button = screen.getByRole('button', { name: 'Enter' })
    await fireEvent.click(button)
    await waitFor(() => expect(server.to('GET', '/api/auth/session')).toHaveLength(1))
    // The login is answered; the session read is not.
    await flush()
    expect(screen.getByRole('button', { name: 'Please wait…' })).toHaveProperty('disabled', true)
    await fireEvent.submit(button.closest('form')!)
    await fireEvent.click(screen.getByRole('button', { name: 'Please wait…' }))
    await flush()
    expect(server.to('POST', '/api/auth/login')).toHaveLength(1)
    expect(server.to('GET', '/api/auth/session')).toHaveLength(1)
    read.resolve(jsonReply(signedIn()))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    await flush()
    expect(onenter).toHaveBeenCalledTimes(1)
    expect(server.to('POST', '/api/auth/login')).toHaveLength(1)
  })

  it('session expired: busy until the session is read; a second submit sends nothing; onenter once', async () => {
    const read = deferred<Response>()
    const server = stubServer({
      'POST /api/auth/reauthenticate': accountReply(),
      'GET /api/auth/session': () => read.promise,
    })
    const onenter = vi.fn()
    render(Door, { session: session({ resumable: true, username: 'ana' }), onenter })
    await type(screen.getByPlaceholderText('password'), 'pw-fake-1')
    const form = screen.getByRole('button', { name: 'Continue' }).closest('form')!
    await fireEvent.submit(form)
    await waitFor(() => expect(server.to('GET', '/api/auth/session')).toHaveLength(1))
    await flush()
    expect(screen.getByRole('button', { name: 'Please wait…' })).toHaveProperty('disabled', true)
    await fireEvent.submit(form)
    await flush()
    expect(server.to('POST', '/api/auth/reauthenticate')).toHaveLength(1)
    read.resolve(jsonReply(signedIn()))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    await flush()
    expect(onenter).toHaveBeenCalledTimes(1)
  })
})

const ph = (p: string) => screen.getByPlaceholderText(p) as HTMLInputElement
const owed = () => session({ authenticated: true, mustEnrolSecondFactor: true, passkeys: { status: 'ready', signIn: false } })

async function toPasskeyForm() {
  render(Door, { session: owed(), onenter: () => {} })
  await fireEvent.click(screen.getByText('Passkey'))
  await type(ph('password'), 'pw-fake-1')
  await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
  await screen.findByPlaceholderText('name')
  await type(ph('name'), 'laptop key')
}

describe('second step refusals', () => {
  it('register/begin 409: says another key is waiting on its codes', async () => {
    stubCredentials()
    stubServer({ 'POST /api/auth/passkeys/register/begin': problem('conflict', 409) })
    await toPasskeyForm()
    await fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }))
    expect((await screen.findByRole('alert')).textContent).toBe('Another key is waiting for its codes to be saved. Try again in ten minutes.')
  })

  it('register/finish 400: says the passkey was not accepted', async () => {
    stubCredentials()
    stubServer({
      'POST /api/auth/passkeys/register/begin': jsonReply({ publicKey: { challenge: 'AQID', rp: { name: 'b' }, user: { id: 'AQID', name: 'ana', displayName: 'ana' }, pubKeyCredParams: [] } }),
      'POST /api/auth/passkeys/register/finish': problem('invalid-request', 400),
    })
    await toPasskeyForm()
    await fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }))
    expect((await screen.findByRole('alert')).textContent).toBe('The passkey was not accepted. Try again.')
  })

  it('Incorrect code. returns focus to the code field', async () => {
    stubServer({
      'POST /api/auth/totp/enrol': jsonReply({ uri: 'otpauth://totp/birdcage:ana?secret=AAAAAAAAAAAAAAAA', secret: 'AAAAAAAAAAAAAAAA' }),
      'POST /api/auth/totp/confirm': problem('invalid-request', 400),
    })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    const field = await screen.findByPlaceholderText('6-digit code')
    await type(field, '000000')
    ;(document.activeElement as HTMLElement | null)?.blur()
    await fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect((await screen.findByRole('alert')).textContent).toBe('Incorrect code.')
    await waitFor(() => expect(document.activeElement).toBe(screen.getByPlaceholderText('6-digit code')))
  })
})

describe('session expired in passkey mode', () => {
  it('Use your password instead goes back to the password, which takes focus', async () => {
    stubServer({})
    render(Door, { session: session({ resumable: true, username: 'ana', passkeys: { status: 'ready', signIn: true } }), onenter: () => {} })
    await fireEvent.click(screen.getByRole('button', { name: 'Use your passkey instead' }))
    expect(screen.queryByPlaceholderText('password')).toBeNull()
    await fireEvent.click(screen.getByRole('button', { name: 'Use your password instead' }))
    await waitFor(() => expect(document.activeElement).toBe(screen.getByPlaceholderText('password')))
    expect(screen.getByRole('heading', { name: 'Session expired' })).toBeTruthy()
  })

  it('the links are disabled while a request is in flight', async () => {
    const gate = deferred<Response>()
    stubServer({ 'POST /api/auth/reauthenticate': () => gate.promise })
    render(Door, { session: session({ resumable: true, username: 'ana', passkeys: { status: 'ready', signIn: true } }), onenter: () => {} })
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await screen.findByRole('button', { name: 'Please wait…' })
    expect(screen.getByRole('button', { name: 'Use your passkey instead' })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: 'Sign in as someone else' })).toHaveProperty('disabled', true)
  })
})
