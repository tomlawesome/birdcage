import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Door from './Door.svelte'
import { accountReply, deferred, flush, jsonReply, problem, session, stubBrowser, stubCredentials, stubServer } from './testkit'

beforeEach(() => stubBrowser())
afterEach(() => vi.unstubAllGlobals())

const type = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } })
const expired = (over: Record<string, unknown> = {}) => session({ resumable: true, ...over })
const pw = () => screen.getByPlaceholderText('password') as HTMLInputElement

describe('session expired', () => {
  it('shows heading, subtitle, password field, Continue and the sign-in-as-someone-else link', () => {
    stubServer({})
    render(Door, { session: expired(), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Session expired' })).toBeTruthy()
    expect(screen.getByText('Enter your password to continue.')).toBeTruthy()
    expect(pw()).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Continue' })).toBeTruthy()
    expect(screen.getByText('Sign in as someone else')).toBeTruthy()
  })

  it('does not show the account field or the Signed-out-at wording from the mock-up', () => {
    stubServer({})
    render(Door, { session: expired(), onenter: () => {} })
    expect(screen.queryByPlaceholderText('account')).toBeNull()
    expect(screen.queryByText(/Signed out at/)).toBeNull()
  })

  it('shows the account name only when the tab knew it', () => {
    stubServer({})
    const a = render(Door, { session: expired({ username: 'ana' }), onenter: () => {} })
    expect(screen.queryByText('ana')).toBeTruthy()
    a.unmount()
    render(Door, { session: expired(), onenter: () => {} })
    expect(screen.queryByText('ana')).toBeNull()
  })

  it('passkey link only when passkeys.signIn', () => {
    stubServer({})
    const a = render(Door, { session: expired({ passkeys: { count: 0, status: 'ready', signIn: true } }), onenter: () => {} })
    expect(screen.getByText('Use your passkey instead')).toBeTruthy()
    a.unmount()
    render(Door, { session: expired({ passkeys: { count: 0, status: 'ready' } }), onenter: () => {} })
    expect(screen.queryByText('Use your passkey instead')).toBeNull()
  })

  it('the right password posts {password} to reauthenticate and calls onenter', async () => {
    const onenter = vi.fn()
    const server = stubServer({ 'POST /api/auth/reauthenticate': accountReply(), 'GET /api/auth/session': jsonReply(session({ authenticated: true })) })
    render(Door, { session: expired(), onenter })
    await type(pw(), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    const r = server.to('POST', '/api/auth/reauthenticate')
    expect(r).toHaveLength(1)
    expect(r[0].body).toEqual({ password: 'pw-fake-1' })
    expect(r[0].headers['x-requested-with']).toBe('birdcage')
  })

  it('an empty password sends nothing', async () => {
    const server = stubServer({})
    render(Door, { session: expired(), onenter: () => {} })
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(server.calls).toHaveLength(0)
  })

  it('401 invalid-credentials: Incorrect password.', async () => {
    const onenter = vi.fn()
    stubServer({ 'POST /api/auth/reauthenticate': problem('invalid-credentials', 401) })
    render(Door, { session: expired(), onenter })
    await type(pw(), 'wrong-fake')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Incorrect password.')
    expect(onenter).not.toHaveBeenCalled()
  })

  it('401 sign-in-required: the sign-in screen', async () => {
    stubServer({ 'POST /api/auth/reauthenticate': problem('sign-in-required', 401) })
    render(Door, { session: expired(), onenter: () => {} })
    await type(pw(), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enter' })).toBeTruthy()
  })

  it('429: try again later, plus the SSO line only when SSO is on', async () => {
    stubServer({ 'POST /api/auth/reauthenticate': problem('rate-limited', 429) })
    const a = render(Door, { session: expired({ ssoAvailable: true }), onenter: () => {} })
    await type(pw(), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await screen.findByText(/Too many attempts\. Try again later\./)
    expect(screen.getByText(/SSO sign-in still works\./)).toBeTruthy()
    a.unmount()
    stubServer({ 'POST /api/auth/reauthenticate': problem('rate-limited', 429) })
    render(Door, { session: expired({ ssoAvailable: false }), onenter: () => {} })
    await type(pw(), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await screen.findByText(/Too many attempts\. Try again later\./)
    expect(screen.queryByText(/SSO sign-in still works\./)).toBeNull()
  })

  it('Sign in as someone else logs out first, then shows sign in', async () => {
    const server = stubServer({ 'POST /api/auth/logout': jsonReply({}), 'GET /api/auth/session': jsonReply(session()) })
    render(Door, { session: expired({ username: 'ana' }), onenter: () => {} })
    await fireEvent.click(screen.getByText('Sign in as someone else'))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    const out = server.to('POST', '/api/auth/logout')
    expect(out).toHaveLength(1)
    expect(out[0].headers['x-requested-with']).toBe('birdcage')
    expect(screen.queryByText('Session expired')).toBeNull()
  })

  it('the sign-in screen is not shown until the logout request has finished', async () => {
    const gate = deferred<Response>()
    stubServer({ 'POST /api/auth/logout': () => gate.promise, 'GET /api/auth/session': jsonReply(session()) })
    render(Door, { session: expired(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Sign in as someone else'))
    await flush()
    expect(screen.queryByPlaceholderText('account')).toBeNull()
    gate.resolve(jsonReply({}))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
  })

  it('the passkey link switches to the passkey screen', async () => {
    stubCredentials()
    stubServer({})
    render(Door, { session: expired({ passkeys: { count: 0, status: 'ready', signIn: true } }), onenter: () => {} })
    await fireEvent.click(screen.getByText('Use your passkey instead'))
    expect(await screen.findByRole('heading', { name: 'Use your passkey' })).toBeTruthy()
  })

  it('double submit sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/reauthenticate': () => gate.promise })
    render(Door, { session: expired(), onenter: () => {} })
    await type(pw(), 'pw-fake-1')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/reauthenticate')).toHaveLength(1)
    gate.resolve(problem('invalid-credentials', 401))
    await screen.findByText('Incorrect password.')
  })
})
