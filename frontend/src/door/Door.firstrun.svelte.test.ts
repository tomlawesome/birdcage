import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Door from './Door.svelte'
import { accountReply, deferred, flush, jsonReply, problem, session, stubBrowser, stubCredentials, stubServer } from './testkit'

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
const heading = (name: string) => screen.findByRole('heading', { name })
const norm = (s: string | null | undefined) => (s ?? '').replace(/\s+/g, '')

// ---------------------------------------------------------------- first run

describe('first run', () => {
  const firstrun = () => session({ setupRequired: true })

  async function fill(over: Partial<Record<'code' | 'account' | 'pw' | 'confirm', string>> = {}) {
    const v = { code: 'setup-fake-1', account: 'ana', pw: 'pw-fake-1', confirm: 'pw-fake-1', ...over }
    await type(ph('setup code'), v.code)
    await type(ph('account'), v.account)
    await type(ph('password'), v.pw)
    await type(ph('confirm password'), v.confirm)
  }

  it('shows heading, subtitle, four fields and the button', () => {
    stubServer({})
    render(Door, { session: firstrun(), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Create the admin account' })).toBeTruthy()
    expect(screen.getByText('No account exists yet. The setup code is in the server log.')).toBeTruthy()
    for (const p of ['setup code', 'account', 'password', 'confirm password']) expect(ph(p)).toBeTruthy()
    expect(btn('Create account')).toBeTruthy()
  })

  it('checks in order, first failure only, sending nothing', async () => {
    const server = stubServer({})
    render(Door, { session: firstrun(), onenter: () => {} })
    const go = () => fireEvent.click(btn('Create account'))
    const alertText = async () => (await screen.findByRole('alert')).textContent ?? ''

    await go()
    let t = await alertText()
    expect(t).toContain('Enter the setup code.')
    expect(t).not.toContain('Enter your account name.')

    await type(ph('setup code'), 'setup-fake-1')
    await go()
    await waitFor(async () => expect(await alertText()).toContain('Enter your account name.'))

    await type(ph('account'), 'ana')
    await go()
    await waitFor(async () => expect(await alertText()).toContain('Enter your password.'))

    await type(ph('password'), 'pw-fake-1')
    await go()
    await waitFor(async () => expect(await alertText()).toContain('Type the password a second time to confirm it.'))

    await type(ph('confirm password'), 'other-fake')
    await go()
    await waitFor(async () => expect(await alertText()).toContain('Passwords do not match.'))
    expect((await alertText()).includes('Enter')).toBe(false)

    expect(server.calls).toHaveLength(0)
  })

  it('posts username, password and setupCode, re-reads the session and continues to the second step', async () => {
    const onenter = vi.fn()
    const server = stubServer({
      'POST /api/auth/register': accountReply(),
      'GET /api/auth/session': jsonReply(session({ authenticated: true, mustEnrolSecondFactor: true })),
    })
    render(Door, { session: firstrun(), onenter })
    await fill()
    await fireEvent.click(btn('Create account'))
    expect(await heading('Add a second step')).toBeTruthy()
    const reg = server.to('POST', '/api/auth/register')
    expect(reg).toHaveLength(1)
    expect(reg[0].body).toEqual({ username: 'ana', password: 'pw-fake-1', setupCode: 'setup-fake-1' })
    expect(reg[0].headers['x-requested-with']).toBe('birdcage')
    expect(server.keys()).toEqual(['POST /api/auth/register', 'GET /api/auth/session'])
    expect(onenter).not.toHaveBeenCalled()
  })

  it('401: Incorrect setup code.', async () => {
    stubServer({ 'POST /api/auth/register': problem('invalid-credentials', 401) })
    render(Door, { session: firstrun(), onenter: () => {} })
    await fill()
    await fireEvent.click(btn('Create account'))
    expect((await screen.findByRole('alert')).textContent).toContain('Incorrect setup code.')
  })

  it('400: shows the server detail', async () => {
    stubServer({ 'POST /api/auth/register': problem('invalid-request', 400, 'Password must be at least 12 characters.') })
    render(Door, { session: firstrun(), onenter: () => {} })
    await fill()
    await fireEvent.click(btn('Create account'))
    expect((await screen.findByRole('alert')).textContent).toContain('Password must be at least 12 characters.')
  })

  it('409: re-reads the session and continues by it', async () => {
    stubServer({
      'POST /api/auth/register': problem('conflict', 409),
      'GET /api/auth/session': jsonReply(session()),
    })
    render(Door, { session: firstrun(), onenter: () => {} })
    await fill()
    await fireEvent.click(btn('Create account'))
    // First run has an account field too: wait for the setup code to go.
    await waitFor(() => expect(screen.queryByPlaceholderText('setup code')).toBeNull())
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(btn('Enter')).toBeTruthy()
  })

  it('429: try again later', async () => {
    stubServer({ 'POST /api/auth/register': problem('rate-limited', 429) })
    render(Door, { session: firstrun(), onenter: () => {} })
    await fill()
    await fireEvent.click(btn('Create account'))
    expect((await screen.findByRole('alert')).textContent).toContain('Too many attempts. Try again later.')
  })

  it('double submit sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/register': () => gate.promise })
    render(Door, { session: firstrun(), onenter: () => {} })
    await fill()
    await fireEvent.click(btn('Create account'))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/register')).toHaveLength(1)
    gate.resolve(problem('invalid-credentials', 401))
    await screen.findByText('Incorrect setup code.')
  })
})

// ----------------------------------------------------------- second step

const SECRET = 'JBSWY3DPEHPK3PXP'
const URI = 'otpauth://totp/birdcage:ana?secret=' + SECRET
// deliberately not in sorted order
const CODES = ['q7m2-x9kd', 'b4n8-t2wz', 'z1c5-h6rj', 'a9p3-v7ls', 'm2d6-f8yg', 'k5t1-w3nb', 'x8h4-c2qe', 'f3v9-r5ju', 'c6s7-p1ma', 'd2g8-y4zk']
const owed = (over: Record<string, unknown> = {}) => session({ authenticated: true, mustEnrolSecondFactor: true, passkeys: { count: 0, status: 'ready' }, ...over })
const enrolReply = () => jsonReply({ uri: URI, secret: SECRET })
const codesReply = () => jsonReply({ recoveryCodes: CODES })

describe('second step: choose', () => {
  it('shows heading, subtitle, both keys and the thread line', () => {
    stubServer({})
    const { container } = render(Door, { session: owed(), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Add a second step' })).toBeTruthy()
    expect(screen.getByText('Every account needs one. Pick a key and prove it works.')).toBeTruthy()
    expect(screen.getByText('Authenticator app')).toBeTruthy()
    expect(screen.getByText('A code from your phone.')).toBeTruthy()
    expect(screen.getByText('Passkey')).toBeTruthy()
    expect(screen.getByText('Fingerprint, face or device PIN.')).toBeTruthy()
    expect(norm(container.textContent)).toContain('choose·proveit·keepthecodes·enter')
  })

  it('has no skip, cancel or sign-out', () => {
    stubServer({})
    render(Door, { session: owed(), onenter: () => {} })
    expect(screen.queryByText(/skip|cancel|sign out/i)).toBeNull()
  })

  it('passkey key is disabled, with the https note instead of its description, unless passkeys are ready', () => {
    stubServer({})
    render(Door, { session: owed({ passkeys: { count: 0, status: 'insecure' } }), onenter: () => {} })
    expect(screen.getByText('The public address is http. Passkeys need https.')).toBeTruthy()
    expect(screen.queryByText('Fingerprint, face or device PIN.')).toBeNull()
    const key = screen.getByText('Passkey').closest('button')
    expect(key?.hasAttribute('disabled')).toBe(true)
    // the neighbouring key is unaffected
    expect(screen.getByText('Authenticator app').closest('button')?.hasAttribute('disabled')).toBe(false)
  })

  it('passkey key is enabled when status is ready', () => {
    stubServer({})
    render(Door, { session: owed(), onenter: () => {} })
    expect(screen.getByText('Passkey').closest('button')?.hasAttribute('disabled')).toBe(false)
    expect(screen.queryByText('Passkeys need an https web address.')).toBeNull()
  })

  it('when mustEnrolPasskey only the passkey key is offered', () => {
    stubServer({})
    render(Door, { session: owed({ mustEnrolSecondFactor: false, mustEnrolPasskey: true }), onenter: () => {} })
    expect(screen.getByText('Passkey')).toBeTruthy()
    expect(screen.queryByText('Authenticator app')).toBeNull()
  })
})

describe('second step: prove it with the authenticator app', () => {
  it('reload case: asks for the password first, then enrols with it', async () => {
    const server = stubServer({ 'POST /api/auth/totp/enrol': enrolReply() })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    const field = ph('password')
    expect(server.to('POST', '/api/auth/totp/enrol')).toHaveLength(0)
    await type(field, 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    expect(await heading('Prove it works')).toBeTruthy()
    const enrol = server.to('POST', '/api/auth/totp/enrol')
    expect(enrol).toHaveLength(1)
    expect(enrol[0].body).toEqual({ password: 'pw-fake-1' })
    expect(enrol[0].headers['x-requested-with']).toBe('birdcage')
  })

  it('a password held from this visit is used without asking again', async () => {
    const server = stubServer({
      'POST /api/auth/login': accountReply(),
      'GET /api/auth/session': jsonReply(owed()),
      'POST /api/auth/totp/enrol': enrolReply(),
    })
    render(Door, { session: session(), onenter: () => {} })
    await type(ph('account'), 'ana')
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Enter'))
    await heading('Add a second step')
    await fireEvent.click(screen.getByText('Authenticator app'))
    expect(await heading('Prove it works')).toBeTruthy()
    expect(screen.queryByPlaceholderText('password')).toBeNull()
    expect(server.to('POST', '/api/auth/totp/enrol')[0].body).toEqual({ password: 'pw-fake-1' })
  })

  async function toProve() {
    const server = stubServer({
      'POST /api/auth/totp/enrol': enrolReply(),
      'POST /api/auth/totp/confirm': codesReply(),
      'POST /api/auth/recovery-codes/confirm': jsonReply({}),
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
    })
    const onenter = vi.fn()
    const view = render(Door, { session: owed(), onenter })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    return { server, onenter, ...view }
  }

  it('shows the text, the secret in groups of four, field, button, note and the passkey link', async () => {
    const { container } = await toProve()
    expect(screen.getByText('Scan this with your authenticator app, then enter the code it shows.')).toBeTruthy()
    expect(screen.getByText('Secret')).toBeTruthy()
    expect(container.textContent?.replace(/\s+/g, ' ')).toContain('JBSW Y3DP EHPK 3PXP')
    expect(ph('6-digit code')).toBeTruthy()
    expect(btn('Confirm')).toBeTruthy()
    expect(screen.getByText('Confirming signs this account out everywhere else.')).toBeTruthy()
    expect(screen.getByText('Use a passkey instead')).toBeTruthy()
  })

  it('omits the passkey link when passkeys are not offered', async () => {
    stubServer({ 'POST /api/auth/totp/enrol': enrolReply() })
    render(Door, { session: owed({ passkeys: { count: 0, status: 'insecure' } }), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    expect(screen.queryByText('Use a passkey instead')).toBeNull()
  })

  it('confirm posts {code} and shows the recovery codes', async () => {
    const { server } = await toProve()
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    expect(await heading('Keep the codes')).toBeTruthy()
    const c = server.to('POST', '/api/auth/totp/confirm')
    expect(c).toHaveLength(1)
    expect(c[0].body).toEqual({ code: '123456' })
  })

  it('400 on confirm: Incorrect code.', async () => {
    stubServer({ 'POST /api/auth/totp/enrol': enrolReply(), 'POST /api/auth/totp/confirm': problem('invalid-request', 400) })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    await type(ph('6-digit code'), '000000')
    await fireEvent.click(btn('Confirm'))
    expect((await screen.findByRole('alert')).textContent).toContain('Incorrect code.')
    expect(screen.getByRole('heading', { name: 'Prove it works' })).toBeTruthy()
  })

  it('401 step-expired on confirm starts the step again with a new secret', async () => {
    const second = 'MFRGGZDFMZTWQ2LK'
    const server = stubServer({
      'POST /api/auth/totp/enrol': [enrolReply(), jsonReply({ uri: 'otpauth://totp/x?secret=' + second, secret: second })],
      'POST /api/auth/totp/confirm': problem('step-expired', 401),
    })
    const { container } = render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await waitFor(() => expect(container.textContent?.replace(/\s+/g, '')).toContain(second))
    expect(server.to('POST', '/api/auth/totp/enrol')).toHaveLength(2)
  })

  it('double submit of Confirm sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/totp/enrol': enrolReply(), 'POST /api/auth/totp/confirm': () => gate.promise })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/totp/confirm')).toHaveLength(1)
    gate.resolve(codesReply())
    await heading('Keep the codes')
  })

  it('double submit of the password Continue sends one enrol request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/totp/enrol': () => gate.promise })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/totp/enrol')).toHaveLength(1)
    gate.resolve(enrolReply())
    await heading('Prove it works')
  })
})

describe('second step: prove it with a passkey', () => {
  // The specification names the calls "register/begin" and "register/finish"
  // without their full path, so the stub matches on that tail.
  function stubPasskeyServer(gate?: Promise<Response>) {
    const calls: { method: string; path: string; body: unknown; headers: Record<string, string> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = typeof input === 'string' ? input : (input as Request).url
        const headers: Record<string, string> = {}
        new Headers(init?.headers).forEach((v, k) => (headers[k.toLowerCase()] = v))
        calls.push({ method: init?.method ?? 'GET', path, body: init?.body ? JSON.parse(init.body as string) : undefined, headers })
        if (path.endsWith('register/begin')) return gate ?? jsonReply({ publicKey: { challenge: 'AQID', user: { id: 'AQID', name: 'ana', displayName: 'ana' }, pubKeyCredParams: [] } })
        if (path.endsWith('register/finish')) return codesReply()
        throw new Error('unexpected request: ' + path)
      }),
    )
    return calls
  }

  async function toPasskeyForm(creds = stubCredentials()) {
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Passkey'))
    if (screen.queryByPlaceholderText('password')) {
      await type(ph('password'), 'pw-fake-1')
      await fireEvent.click(btn('Continue'))
    }
    await heading('Prove it works')
    return creds
  }

  it('shows the text, name field, Add passkey and the authenticator link', async () => {
    stubCredentials()
    stubServer({})
    await toPasskeyForm()
    expect(screen.getByText('Name this passkey. Your browser asks for the fingerprint, face or PIN.')).toBeTruthy()
    expect(ph('name')).toBeTruthy()
    expect(btn('Add passkey')).toBeTruthy()
    expect(screen.getByText('Use an authenticator app instead')).toBeTruthy()
  })

  it('calls begin with the password, the browser prompt, then finish with credential and name; then shows the codes', async () => {
    const creds = stubCredentials()
    const calls = stubPasskeyServer()
    await toPasskeyForm(creds)
    await type(ph('name'), 'laptop key')
    await fireEvent.click(btn('Add passkey'))
    expect(await heading('Keep the codes')).toBeTruthy()
    const tails = calls.map((c) => c.path.split('/').slice(-2).join('/'))
    expect(tails).toEqual(['register/begin', 'register/finish'])
    expect(calls[0].method).toBe('POST')
    expect(calls[0].body).toEqual({ password: 'pw-fake-1' })
    expect(calls[0].headers['x-requested-with']).toBe('birdcage')
    expect(creds.create).toHaveBeenCalledTimes(1)
    const fin = calls[1].body as Record<string, unknown>
    expect(fin.name).toBe('laptop key')
    expect(fin.credential).toBeTruthy()
  })

  it('shows Waiting… (disabled) during the prompt and does not prompt twice', async () => {
    const creds = stubCredentials()
    const prompt = deferred<unknown>()
    creds.create.mockImplementation(() => prompt.promise as never)
    stubPasskeyServer()
    await toPasskeyForm(creds)
    await type(ph('name'), 'laptop key')
    await fireEvent.click(btn('Add passkey'))
    const waiting = await screen.findByRole('button', { name: 'Waiting…' })
    expect(waiting.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(waiting)
    await fireEvent.submit(waiting.closest('form') ?? waiting)
    await flush()
    expect(creds.create).toHaveBeenCalledTimes(1)
  })

  it('double submit sends one begin request', async () => {
    stubCredentials()
    const gate = deferred<Response>()
    const calls = stubPasskeyServer(gate.promise)
    await toPasskeyForm()
    await type(ph('name'), 'laptop key')
    await fireEvent.click(btn('Add passkey'))
    const wait = await screen.findByRole('button', { name: /Please wait…|Waiting…/ })
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(calls.filter((c) => c.path.endsWith('register/begin'))).toHaveLength(1)
  })
})

describe('second step: keep the codes', () => {
  async function toCodes() {
    const server = stubServer({
      'POST /api/auth/totp/enrol': enrolReply(),
      'POST /api/auth/totp/confirm': codesReply(),
      'POST /api/auth/recovery-codes/confirm': jsonReply({}),
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
    })
    const onenter = vi.fn()
    const view = render(Door, { session: owed(), onenter })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await heading('Keep the codes')
    return { server, onenter, ...view }
  }

  it('shows heading text, thread line and buttons', async () => {
    const { container } = await toCodes()
    expect(screen.getByText('Ten recovery codes. Each works once in place of your second step. They are not shown again.')).toBeTruthy()
    expect(btn('Copy all')).toBeTruthy()
    expect(btn('Download')).toBeTruthy()
    expect(btn('I have saved these')).toBeTruthy()
    expect(norm(container.textContent)).toContain('choose·proveit·keepthecodes·enter')
  })

  it('shows all ten codes in the order sent', async () => {
    await toCodes()
    const els = CODES.map((c) => screen.getByText(c))
    for (let i = 1; i < els.length; i++) {
      expect(els[i - 1].compareDocumentPosition(els[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
    expect(els).toHaveLength(10)
  })

  it('Copy all writes all ten codes and the button becomes Copied', async () => {
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await toCodes()
    await fireEvent.click(btn('Copy all'))
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    const written = (writeText.mock.calls[0] as unknown as string[])[0]
    expect(written.split(/\s+/).filter(Boolean)).toEqual(CODES)
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeTruthy()
  })

  it('Download offers a text file with one code per line', async () => {
    let blob: Blob | undefined
    ;(URL as unknown as { createObjectURL: unknown }).createObjectURL = vi.fn((b: Blob) => {
      blob = b
      return 'blob:fake'
    })
    ;(URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await toCodes()
    await fireEvent.click(btn('Download'))
    await waitFor(() => expect(blob).toBeTruthy())
    expect(blob!.type).toMatch(/^text\/plain/)
    const text = await blob!.text()
    expect(text.trim().split(/\r?\n/)).toEqual(CODES)
  })

  it('writes nothing to localStorage or sessionStorage and not to the address', async () => {
    const set = vi.spyOn(Storage.prototype, 'setItem')
    await toCodes()
    expect(set).not.toHaveBeenCalled()
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
    for (const c of CODES) expect(location.href).not.toContain(c)
  })

  it('does not log the codes', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => {}))
    await toCodes()
    const logged = JSON.stringify(spies.flatMap((s) => s.mock.calls))
    for (const c of CODES) expect(logged).not.toContain(c)
  })

  it('I have saved these posts the confirmation, re-reads the session, then enters', async () => {
    const { server, onenter } = await toCodes()
    await fireEvent.click(btn('I have saved these'))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    const keys = server.keys()
    expect(keys.slice(-2)).toEqual(['POST /api/auth/recovery-codes/confirm', 'GET /api/auth/session'])
    expect(server.to('POST', '/api/auth/recovery-codes/confirm')[0].headers['x-requested-with']).toBe('birdcage')
  })

  it('double submit of I have saved these sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({
      'POST /api/auth/totp/enrol': enrolReply(),
      'POST /api/auth/totp/confirm': codesReply(),
      'POST /api/auth/recovery-codes/confirm': () => gate.promise,
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
    })
    render(Door, { session: owed(), onenter: () => {} })
    await fireEvent.click(screen.getByText('Authenticator app'))
    await type(ph('password'), 'pw-fake-1')
    await fireEvent.click(btn('Continue'))
    await heading('Prove it works')
    await type(ph('6-digit code'), '123456')
    await fireEvent.click(btn('Confirm'))
    await heading('Keep the codes')
    await fireEvent.click(btn('I have saved these'))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/recovery-codes/confirm')).toHaveLength(1)
    gate.resolve(jsonReply({}))
  })
})

// ----------------------------------------------------------- new password

describe('set a new password', () => {
  const needs = () => session({ authenticated: true, mustChangePassword: true })

  it('shows the text, two fields and the button', () => {
    stubServer({})
    render(Door, { session: needs(), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Set a new password' })).toBeTruthy()
    expect(screen.getByText('Your one-time code got you in. Choose a password only you know.')).toBeTruthy()
    expect(ph('new password')).toBeTruthy()
    expect(ph('confirm password')).toBeTruthy()
    expect(btn('Set password')).toBeTruthy()
  })

  it('posts {newPassword}, re-reads the session and enters', async () => {
    const onenter = vi.fn()
    const server = stubServer({
      'POST /api/auth/password': jsonReply({}),
      'GET /api/auth/session': jsonReply(session({ authenticated: true })),
    })
    render(Door, { session: needs(), onenter })
    await type(ph('new password'), 'new-fake-pass-1')
    await type(ph('confirm password'), 'new-fake-pass-1')
    await fireEvent.click(btn('Set password'))
    await waitFor(() => expect(onenter).toHaveBeenCalledTimes(1))
    const p = server.to('POST', '/api/auth/password')
    expect(p).toHaveLength(1)
    expect(p[0].body).toEqual({ newPassword: 'new-fake-pass-1' })
    expect(p[0].headers['x-requested-with']).toBe('birdcage')
  })

  it('400 shows the server detail', async () => {
    stubServer({ 'POST /api/auth/password': problem('invalid-request', 400, 'Choose a different password.') })
    render(Door, { session: needs(), onenter: () => {} })
    await type(ph('new password'), 'new-fake-pass-1')
    await type(ph('confirm password'), 'new-fake-pass-1')
    await fireEvent.click(btn('Set password'))
    expect((await screen.findByRole('alert')).textContent).toContain('Choose a different password.')
  })

  it('mismatched confirmation sends nothing', async () => {
    const server = stubServer({})
    render(Door, { session: needs(), onenter: () => {} })
    await type(ph('new password'), 'new-fake-pass-1')
    await type(ph('confirm password'), 'different-fake')
    await fireEvent.click(btn('Set password'))
    expect((await screen.findByRole('alert')).textContent).toContain('Passwords do not match.')
    expect(server.calls).toHaveLength(0)
  })

  it('double submit sends one request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'POST /api/auth/password': () => gate.promise })
    render(Door, { session: needs(), onenter: () => {} })
    await type(ph('new password'), 'new-fake-pass-1')
    await type(ph('confirm password'), 'new-fake-pass-1')
    await fireEvent.click(btn('Set password'))
    const wait = await screen.findByRole('button', { name: 'Please wait…' })
    expect(wait.hasAttribute('disabled')).toBe(true)
    await fireEvent.click(wait)
    await fireEvent.submit(wait.closest('form') ?? wait)
    await flush()
    expect(server.to('POST', '/api/auth/password')).toHaveLength(1)
    gate.resolve(problem('invalid-request', 400, 'x'))
    await screen.findByRole('alert')
  })
})

// Issue #164 item 7: SSO is refused while no account exists, so the
// first-run screen offers no SSO link even when the session says SSO is
// configured. (The sign-in screen still shows it.)
describe('first run with SSO configured', () => {
  it('shows no SSO link', () => {
    stubServer({})
    render(Door, { session: session({ setupRequired: true, ssoAvailable: true }), onenter: () => {} })
    expect(screen.getByRole('heading', { name: 'Create the admin account' })).toBeTruthy()
    expect(screen.queryByText('Sign in with SSO')).toBeNull()
    expect(screen.queryByRole('link', { name: /sso/i })).toBeNull()
  })
})
