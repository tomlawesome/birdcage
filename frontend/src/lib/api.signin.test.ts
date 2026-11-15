import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, getJSON, onSignedOut, sendJSON } from './api'
import { jsonReply, problem, stubServer } from '../door/testkit'

afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

describe('sendJSON', () => {
  it.each(['POST', 'PUT', 'DELETE', 'PATCH'])('sends X-Requested-With: birdcage on %s with no body', async (method) => {
    const server = stubServer({ [`${method} /api/x`]: jsonReply({ ok: true }) })
    await sendJSON(method, '/api/x')
    expect(server.calls[0].method).toBe(method)
    expect(server.calls[0].headers['x-requested-with']).toBe('birdcage')
    expect(server.calls[0].rawBody).toBeUndefined()
  })

  it('sends the JSON body with its content type when one is given', async () => {
    const server = stubServer({ 'POST /api/x': jsonReply({ ok: true }) })
    await sendJSON('POST', '/api/x', { a: 1, b: 'two' })
    expect(server.calls[0].headers['content-type']).toBe('application/json')
    expect(server.calls[0].headers['x-requested-with']).toBe('birdcage')
    expect(server.calls[0].body).toEqual({ a: 1, b: 'two' })
  })

  it('sends no content type when there is no body', async () => {
    const server = stubServer({ 'POST /api/x': jsonReply({}) })
    await sendJSON('POST', '/api/x')
    expect(server.calls[0].headers['content-type']).toBeUndefined()
  })

  it('returns the parsed JSON of a 2xx', async () => {
    stubServer({ 'POST /api/x': jsonReply({ hello: 'world' }, 201) })
    await expect(sendJSON('POST', '/api/x', {})).resolves.toEqual({ hello: 'world' })
  })

  it('puts nothing in the URL', async () => {
    const server = stubServer({ 'POST /api/x': jsonReply({}) })
    await sendJSON('POST', '/api/x', { password: 'hunter2-fake' })
    expect(server.calls[0].path).toBe('/api/x')
  })

  it('throws ApiError with status, kind (text after #) and detail from a problem body', async () => {
    stubServer({ 'POST /api/x': problem('invalid-credentials', 401, 'nope') })
    const err = await sendJSON('POST', '/api/x', {}).catch((e: ApiError) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(401)
    expect(err.kind).toBe('invalid-credentials')
    expect(err.detail).toBe('nope')
  })

  it.each(['rate-limited', 'step-expired', 'sign-in-required', 'invalid-request', 'conflict', 'setup-required'])('kind %s', async (kind) => {
    stubServer({ 'POST /api/x': problem(kind, 400) })
    const err = await sendJSON('POST', '/api/x', {}).catch((e: ApiError) => e)
    expect(err.kind).toBe(kind)
  })

  it('kind is empty when the body is not a problem document', async () => {
    stubServer({ 'POST /api/x': new Response('<html>bad gateway</html>', { status: 502, headers: { 'Content-Type': 'text/html' } }) })
    const err = await sendJSON('POST', '/api/x', {}).catch((e: ApiError) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(502)
    expect(err.kind).toBe('')
  })

  it('kind is empty for a JSON error body that is not a problem document', async () => {
    stubServer({ 'POST /api/x': jsonReply({ error: 'boom' }, 500) })
    const err = await sendJSON('POST', '/api/x', {}).catch((e: ApiError) => e)
    expect(err.status).toBe(500)
    expect(err.kind).toBe('')
  })
})

describe('getJSON and the signed-out handler', () => {
  it('a 401 calls the handler once and still throws ApiError', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'GET /api/canaries': new Response('', { status: 401 }) })
    const err = await getJSON('/api/canaries').catch((e: ApiError) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(401)
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('other failures do not call the handler', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'GET /api/a': new Response('', { status: 500 }), 'GET /api/b': new Response('', { status: 403 }), 'GET /api/c': new Response('', { status: 404 }) })
    for (const p of ['/api/a', '/api/b', '/api/c']) await getJSON(p).catch(() => {})
    expect(handler).not.toHaveBeenCalled()
  })

  it('a success returns the body and does not call the handler', async () => {
    const handler = vi.fn()
    onSignedOut(handler)
    stubServer({ 'GET /api/ok': jsonReply({ n: 1 }) })
    await expect(getJSON('/api/ok')).resolves.toEqual({ n: 1 })
    expect(handler).not.toHaveBeenCalled()
  })

  it('a 401 with no handler registered still throws ApiError', async () => {
    stubServer({ 'GET /api/x': new Response('', { status: 401 }) })
    await expect(getJSON('/api/x')).rejects.toBeInstanceOf(ApiError)
  })
})
