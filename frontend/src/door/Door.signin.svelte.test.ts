/// <reference types="node" />
// node:fs reads the shipped CSS for the never-red check; vitest runs in Node.
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import Door from './Door.svelte'
import { accountReply, deferred, flush, jsonReply, problem, proveReply, secondFactorReply, session, stubBrowser, stubCredentials, stubServer } from './testkit'

beforeEach(() => stubBrowser())
afterEach(() => {
  vi.unstubAllGlobals()
  history.replaceState(null, '', '/')
})

const type = (el: HTMLElement, value: string) => fireEvent.input(el, { target: { value } })
const account = () => screen.getByPlaceholderText('account') as HTMLInputElement
const password = () => screen.getByPlaceholderText('password') as HTMLInputElement
const enter = () => screen.getByRole('button', { name: 'Enter' })

async function submit(user = 'ana', pw = 'pw-fake-1') {
  await type(account(), user)
  await type(password(), pw)
  await fireEvent.click(enter())
}

describe('sign in screen', () => {
  it('shows the fields and the Enter button', () => {
    stubServer({})
    render(Door, { session: session(), onenter: () => {} })
    expect(account()).toBeTruthy()
    expect(password()).toBeTruthy()
    expect(enter()).toBeTruthy()
  })

  it('shows the divider and SSO link only when ssoAvailable', () => {
    stubServer({})
    render(Door, { session: session({ ssoAvailable: true }), onenter: () => {} })
    expect(screen.getByText('or')).toBeTruthy()
    const link = screen.getByRole('link', { name: 'Sign in with SSO' })
    expect(link.getAttribute('href')).toBe('/api/auth/oidc/login')
  })

  it('shows neither divider nor SSO link when ssoAvailable is false', () => {
    stubServer({})
    render(Door, { session: session({ ssoAvailable: false }), onenter: () => {} })
    expect(screen.queryByText('or')).toBeNull()
    expect(screen.queryByRole('link', { name: 'Sign in with SSO' })).toBeNull()
  })

  it('an empty account says so and sends nothing', async () => {
    const server = stubServer({})
    render(Door, { session: session(), onenter: () => {} })
    await type(password(), 'pw-fake-1')
    await fireEvent.click(enter())
    expect((await screen.findByRole('alert')).textContent).toContain('Enter your account name.')
    expect(server.calls).toHaveLength(0)
  })

  it('an empty password says so and sends nothing', async () => {
    const server = stubServer({})
    render(Door, { session: session(), onenter: () => {} })
    await type(account(), 'ana')
    await fireEvent.click(enter())
    expect((await screen.findByRole('alert')).textContent).toContain('Enter your password.')
    expect(server.calls).toHaveLength(0)
  })

  it('posts username and password with the header, then re-reads the session and enters', async () => {
    const onenter = vi.fn()
    const server = stubServer({
      'POST /api/auth/login': accountReply(),
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
    })
    render(Door, { session: session(), onenter })
    await submit('ana', 'pw-fake-1')
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    const login = server.to('POST', '/api/auth/login')
    expect(login).toHaveLength(1)
    expect(login[0].body).toEqual({ username: 'ana', password: 'pw-fake-1' })
    expect(login[0].headers['x-requested-with']).toBe('birdcage')
    expect(login[0].headers['content-type']).toBe('application/json')
    expect(login[0].path).not.toContain('pw-fake-1')
    expect(server.keys()).toEqual(['POST /api/auth/login', 'GET /api/auth/session'])
  })

  it('continues by doorFor when the re-read session still owes something (no onenter)', async () => {
    const onenter = vi.fn()
    stubServer({
      'POST /api/auth/login': accountReply(),
      'GET /api/auth/session': jsonReply(session({ authenticated: true, mustEnrolSecondFactor: true })),
    })
    render(Door, { session: session(), onenter })
    await submit()
    expect(await screen.findByRole('heading', { name: 'Add a second step' })).toBeTruthy()
    expect(onenter).not.toHaveBeenCalled()
  })

  it('401 invalid-credentials: message, password cleared and focused, account kept, never red', async () => {
    stubServer({ 'POST /api/auth/login': problem('invalid-credentials', 401, 'no such account') })
    render(Door, { session: session(), onenter: () => {} })
    await submit('ana', 'wrong-fake')
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Incorrect account or password.')
    expect(password().value).toBe('')
    expect(document.activeElement).toBe(password())
    expect(account().value).toBe('ana')
    // vitest does not load CSS (an import, even ?raw, comes back empty),
    // so with nothing more every colour reads as the default and a red
    // alert would pass. Load the shipped app and door styles into the
    // page from disk: jsdom then cascades them and resolves var(--ink),
    // so the alert's colour is the one a browser would show.
    const css = (f: string) => readFileSync(new URL(f, import.meta.url), 'utf8')
    const style = document.createElement('style')
    style.textContent = css('../app.css') + '\n' + css('./door.css')
    document.head.append(style)
    try {
      const ink = getComputedStyle(document.documentElement).getPropertyValue('--ink').trim()
      expect(ink).toMatch(/^#[0-9a-f]{6}$/i)
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(ink.slice(i, i + 2), 16))
      // Ink text, never red (ADR-0017 decision 1).
      expect(getComputedStyle(alert).color).toBe(`rgb(${r}, ${g}, ${b})`)
      expect(getComputedStyle(alert).color).not.toMatch(/^(red|rgb\(\s*255,\s*0,\s*0\s*\))$/)
    } finally {
      style.remove()
    }
  })

  it('the refusal text is identical whatever the detail says', async () => {
    const texts: string[] = []
    for (const detail of ['account does not exist', 'wrong password for account', '']) {
      stubServer({ 'POST /api/auth/login': problem('invalid-credentials', 401, detail) })
      const { unmount } = render(Door, { session: session(), onenter: () => {} })
      await submit()
      texts.push((await screen.findByRole('alert')).textContent ?? '')
      unmount()
    }
    expect(new Set(texts).size).toBe(1)
    expect(texts[0]).not.toContain('account does not exist')
  })

  it('429 says to try later, with the SSO line only when SSO is on', async () => {
    stubServer({ 'POST /api/auth/login': problem('rate-limited', 429) })
    const a = render(Door, { session: session({ ssoAvailable: true }), onenter: () => {} })
    await submit()
    await screen.findByText(/Too many attempts\. Try again later\./)
    expect(screen.getByText(/SSO sign-in still works\./)).toBeTruthy()
    a.unmount()

    stubServer({ 'POST /api/auth/login': problem('rate-limited', 429) })
    render(Door, { session: session({ ssoAvailable: false }), onenter: () => {} })
    await submit()
    await screen.findByText(/Too many attempts\. Try again later\./)
    expect(screen.queryByText(/SSO sign-in still works\./)).toBeNull()
  })

  it('429 leaves the fields usable', async () => {
    stubServer({ 'POST /api/auth/login': problem('rate-limited', 429) })
    render(Door, { session: session(), onenter: () => {} })
    await submit()
    await screen.findByText(/Too many attempts/)
    expect(account().disabled).toBe(false)
    expect(password().disabled).toBe(false)
    expect(enter().hasAttribute('disabled')).toBe(false)
  })

  it('a server error says Sign-in failed', async () => {
    stubServer({ 'POST /api/auth/login': problem('internal', 500) })
    render(Door, { session: session(), onenter: () => {} })
    await submit()
    expect((await screen.findByRole('alert')).textContent).toContain('Sign-in failed. Try again.')
  })

  it('a confirm challenge (#189) also says Sign-in failed', async () => {
    // gauntlet v0.4.2's ConfirmationChallenge: exactly {confirm: true}.
    stubServer({ 'POST /api/auth/login': jsonReply({ confirm: true }) })
    render(Door, { session: session(), onenter: () => {} })
    await submit()
    expect((await screen.findByRole('alert')).textContent).toContain('Sign-in failed. Try again.')
  })

  it('a network failure says Sign-in failed', async () => {
    stubServer({ 'POST /api/auth/login': () => Promise.reject(new TypeError('network')) })
    render(Door, { session: session(), onenter: () => {} })
    await submit()
    expect((await screen.findByRole('alert')).textContent).toContain('Sign-in failed. Try again.')
  })

  it('shows Please wait… and disables the button while in flight; a double submit sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/login': () => gate.promise })
    render(Door, { session: session(), onenter: () => {} })
    await type(account(), 'ana')
    await type(password(), 'pw-fake-1')
    await fireEvent.click(enter())
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await fireEvent.keyDown(password(), { key: 'Enter' })
    await flush()
    expect(server.to('POST', '/api/auth/login')).toHaveLength(1)
    gate.resolve(problem('invalid-credentials', 401))
    await screen.findByText('Incorrect account or password.')
    expect(screen.getByRole('button', { name: 'Enter' }).hasAttribute('disabled')).toBe(false)
  })
})

describe('code step', () => {
  async function toCodeStep(methods: string[], extra: Record<string, never> = {}) {
    const server = stubServer({
      'POST /api/auth/login': secondFactorReply(methods),
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
      ...extra,
    })
    const onenter = vi.fn()
    render(Door, { session: session(), onenter })
    await submit()
    return { server, onenter }
  }
  const sub = {
    totp: 'Your password was right. Enter the current code from your authenticator app to finish signing in.',
    recovery: 'Your password was right. Enter one of your recovery codes to finish signing in.',
    passkey: 'Your password was right. Use your passkey to finish signing in.',
  }

  it('[totp]: authenticator text, recovery link, no passkey link', async () => {
    await toCodeStep(['totp'])
    expect(await screen.findByRole('heading', { name: 'Enter your code' })).toBeTruthy()
    expect(screen.getByText(sub.totp)).toBeTruthy()
    expect(screen.getByPlaceholderText('6-digit code')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Continue' })).toBeTruthy()
    expect(screen.getByText('Use a recovery code instead')).toBeTruthy()
    expect(screen.queryByText('Use your passkey instead')).toBeNull()
  })

  it('[totp, passkey]: both links', async () => {
    await toCodeStep(['totp', 'passkey'])
    await screen.findByRole('heading', { name: 'Enter your code' })
    expect(screen.getByText('Use your passkey instead')).toBeTruthy()
    expect(screen.getByText('Use a recovery code instead')).toBeTruthy()
  })

  it('recovery mode text and the way back', async () => {
    await toCodeStep(['totp'])
    await fireEvent.click(await screen.findByText('Use a recovery code instead'))
    expect(screen.getByText(sub.recovery)).toBeTruthy()
    expect(screen.getByPlaceholderText('recovery code')).toBeTruthy()
    await fireEvent.click(screen.getByText('Use your authenticator app instead'))
    expect(screen.getByText(sub.totp)).toBeTruthy()
    expect(screen.getByPlaceholderText('6-digit code')).toBeTruthy()
  })

  it('[passkey] only: passkey screen, no code field', async () => {
    stubCredentials()
    await toCodeStep(['passkey'])
    expect(await screen.findByRole('heading', { name: 'Use your passkey' })).toBeTruthy()
    expect(screen.getByText(sub.passkey)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Use your passkey' })).toBeTruthy()
    expect(screen.queryByPlaceholderText('6-digit code')).toBeNull()
  })

  it('[totp, passkey]: choosing the passkey shows the passkey screen', async () => {
    stubCredentials()
    await toCodeStep(['totp', 'passkey'])
    await fireEvent.click(await screen.findByText('Use your passkey instead'))
    expect(screen.getByRole('heading', { name: 'Use your passkey' })).toBeTruthy()
    expect(screen.getByText(sub.passkey)).toBeTruthy()
  })

  it('empty code: asks for it and sends nothing', async () => {
    const { server } = await toCodeStep(['totp'])
    await fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Enter the code from your app.')
    expect(server.to('POST', '/api/auth/login/factor')).toHaveLength(0)
  })

  it('empty recovery code: asks for it and sends nothing', async () => {
    const { server } = await toCodeStep(['totp'])
    await fireEvent.click(await screen.findByText('Use a recovery code instead'))
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Enter a recovery code.')
    expect(server.to('POST', '/api/auth/login/factor')).toHaveLength(0)
  })

  it('a right code posts {code}, re-reads the session and enters', async () => {
    const { server, onenter } = await toCodeStep(['totp'], { 'POST /api/auth/login/factor': accountReply() } as never)
    await type(await screen.findByPlaceholderText('6-digit code'), '123456')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    const f = server.to('POST', '/api/auth/login/factor')
    expect(f).toHaveLength(1)
    expect(f[0].body).toEqual({ code: '123456' })
    expect(f[0].headers['x-requested-with']).toBe('birdcage')
    expect(server.keys().slice(-1)).toEqual(['GET /api/auth/session'])
  })

  it('a recovery code is posted the same way', async () => {
    const { server, onenter } = await toCodeStep(['totp'], { 'POST /api/auth/login/factor': accountReply() } as never)
    await fireEvent.click(await screen.findByText('Use a recovery code instead'))
    await type(screen.getByPlaceholderText('recovery code'), 'abcd-efgh-ijkl')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(onenter).toHaveBeenCalled())
    expect(server.to('POST', '/api/auth/login/factor')[0].body).toEqual({ code: 'abcd-efgh-ijkl' })
  })

  it('401 invalid-credentials: Incorrect code. and the field is cleared', async () => {
    await toCodeStep(['totp'], { 'POST /api/auth/login/factor': problem('invalid-credentials', 401) } as never)
    const field = (await screen.findByPlaceholderText('6-digit code')) as HTMLInputElement
    await type(field, '000000')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Incorrect code.')
    expect(field.value).toBe('')
  })

  it('401 step-expired: back to sign in with the timed-out message', async () => {
    await toCodeStep(['totp'], { 'POST /api/auth/login/factor': problem('step-expired', 401) } as never)
    await type(await screen.findByPlaceholderText('6-digit code'), '123456')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByText(/Your sign-in timed out\. Enter your password again\./)).toBeTruthy()
    expect(screen.getByPlaceholderText('account')).toBeTruthy()
    expect(screen.getByPlaceholderText('password')).toBeTruthy()
  })

  it('429: try again later', async () => {
    await toCodeStep(['totp'], { 'POST /api/auth/login/factor': problem('rate-limited', 429) } as never)
    await type(await screen.findByPlaceholderText('6-digit code'), '123456')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Too many attempts. Try again later.')
  })

  it('a prove challenge moves to passkey mode and uses the prove endpoints', async () => {
    stubCredentials()
    const { server } = await toCodeStep(['totp'], {
      'POST /api/auth/login/factor': proveReply(),
      'POST /api/auth/login/prove/begin': jsonReply({ publicKey: { challenge: 'AQID' } }),
      'POST /api/auth/login/prove': accountReply(),
    } as never)
    await type(await screen.findByPlaceholderText('6-digit code'), '123456')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    expect(await screen.findByRole('heading', { name: 'Use your passkey' })).toBeTruthy()
    await fireEvent.click(screen.getByRole('button', { name: 'Use your passkey' }))
    await waitFor(() => expect(server.to('POST', '/api/auth/login/prove')).toHaveLength(1))
    const keys = server.keys()
    expect(keys.indexOf('POST /api/auth/login/prove/begin')).toBeLessThan(keys.indexOf('POST /api/auth/login/prove'))
    expect(keys).not.toContain('POST /api/auth/login/factor/begin')
  })

  it('passkey mode calls factor/begin then factor, and shows Waiting… during the prompt', async () => {
    const creds = stubCredentials()
    const prompt = deferred<unknown>()
    creds.get.mockImplementation(() => prompt.promise as never)
    const { server } = await toCodeStep(['passkey'], {
      'POST /api/auth/login/factor/begin': jsonReply({ publicKey: { challenge: 'AQID' } }),
      'POST /api/auth/login/factor': accountReply(),
    } as never)
    await fireEvent.click(await screen.findByRole('button', { name: 'Use your passkey' }))
    const waiting = await screen.findByRole('button', { name: 'Waiting…' })
    expect(waiting.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(waiting)
    await flush()
    expect(server.to('POST', '/api/auth/login/factor/begin')).toHaveLength(1)
    prompt.resolve(await creds.create())
    await waitFor(() => expect(server.to('POST', '/api/auth/login/factor')).toHaveLength(1))
    const keys = server.keys()
    expect(keys.indexOf('POST /api/auth/login/factor/begin')).toBeLessThan(keys.indexOf('POST /api/auth/login/factor'))
    expect(creds.get).toHaveBeenCalledTimes(1)
  })

  it('double submit of the code sends one request', async () => {
    const gate = deferred<Response>()
    const { server } = await toCodeStep(['totp'], { 'POST /api/auth/login/factor': () => gate.promise } as never)
    await type(await screen.findByPlaceholderText('6-digit code'), '123456')
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/login/factor')).toHaveLength(1)
    gate.resolve(problem('invalid-credentials', 401))
    await screen.findByText('Incorrect code.')
  })
})

describe('?ssoError', () => {
  it('not_permitted shows its sentence and removes the query', async () => {
    stubServer({})
    history.replaceState(null, '', '/?ssoError=not_permitted')
    render(Door, { session: session(), onenter: () => {} })
    expect(await screen.findByText('Your account signed in but is not permitted to use this birdcage.')).toBeTruthy()
    expect(location.search).toBe('')
  })

  it('any other code shows the general sentence and removes the query', async () => {
    stubServer({})
    history.replaceState(null, '', '/?ssoError=whatever_else')
    render(Door, { session: session(), onenter: () => {} })
    expect(await screen.findByText('SSO sign-in failed. Try again, or sign in with your password.')).toBeTruthy()
    expect(screen.queryByText(/not permitted/)).toBeNull()
    expect(location.search).toBe('')
  })

  it('without the query neither sentence shows', () => {
    stubServer({})
    render(Door, { session: session(), onenter: () => {} })
    expect(screen.queryByText(/SSO sign-in failed/)).toBeNull()
    expect(screen.queryByText(/not permitted/)).toBeNull()
  })

  it('keeps other query parameters', async () => {
    stubServer({})
    history.replaceState(null, '', '/?ssoError=x&scene=quiet')
    render(Door, { session: session(), onenter: () => {} })
    await screen.findByText(/SSO sign-in failed/)
    expect(location.search).toBe('?scene=quiet')
  })
})
