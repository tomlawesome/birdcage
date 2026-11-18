// Issue #210 (comment of 2026-11-16): sendJSON routes a 401 or a gate 403
// to the signed-out handler exactly as getJSON does.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, onSignedOut, sendJSON } from './api'
import { jsonReply, problem, stubServer } from '../door/testkit'

afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

const GATES = ['must-change-password', 'must-enrol-factor', 'must-enrol-passkey']

describe('sendJSON and the signed-out handler', () => {
  it('a 401 calls the handler once and still throws ApiError', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/canaries/x': new Response('', { status: 401 }) })
    const err = await sendJSON('POST', '/api/canaries/x', {}).catch((e: ApiError) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(401)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it.each(GATES)('a 403 naming gate %s in X-Auth-Gate calls the handler', async (gate) => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/canaries/x': new Response('', { status: 403, headers: { 'X-Auth-Gate': gate } }) })
    const err = await sendJSON('POST', '/api/canaries/x', {}).catch((e: ApiError) => e)
    expect(err.status).toBe(403)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it.each(GATES)('a 403 problem of type #%s calls the handler and keeps kind and detail', async (gate) => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/canaries/x': problem(gate, 403, 'finish first') })
    const err = await sendJSON('POST', '/api/canaries/x', {}).catch((e: ApiError) => e)
    expect(err.kind).toBe(gate)
    expect(err.detail).toBe('finish first')
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('a plain 403, 404 and 500 do not call the handler', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/canaries/a': new Response('', { status: 500 }), 'POST /api/canaries/b': new Response('', { status: 403 }), 'POST /api/canaries/c': problem('forbidden', 403) , 'POST /api/canaries/d': new Response('', { status: 404 }) })
    for (const p of ['/api/canaries/a', '/api/canaries/b', '/api/canaries/c', '/api/canaries/d']) await sendJSON('POST', p, {}).catch(() => {})
    expect(handler).not.toHaveBeenCalled()
  })

  it('a success does not call the handler', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/canaries/ok': jsonReply({ n: 1 }) })
    await expect(sendJSON('POST', '/api/canaries/ok', {})).resolves.toEqual({ n: 1 })
    expect(handler).not.toHaveBeenCalled()
  })

  it('a 401 with no handler registered still throws ApiError', async () => {
    stubServer({ 'POST /api/canaries/x': new Response('', { status: 401 }) })
    await expect(sendJSON('POST', '/api/canaries/x', {})).rejects.toBeInstanceOf(ApiError)
  })

  it('a 401 on an /api/auth/ path does not call the handler (the door handles it)', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/auth/login': new Response('', { status: 401 }) })
    const err = await sendJSON('POST', '/api/auth/login', {}).catch((e: ApiError) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(401)
    expect(handler).not.toHaveBeenCalled()
  })

  it.each(GATES)('a 403 gate %s on an /api/auth/ path does not call the handler', async (gate) => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'POST /api/auth/totp/enrol': new Response('', { status: 403, headers: { 'X-Auth-Gate': gate } }) })
    const err = await sendJSON('POST', '/api/auth/totp/enrol', {}).catch((e: ApiError) => e)
    expect(err.status).toBe(403)
    expect(handler).not.toHaveBeenCalled()
  })
})
