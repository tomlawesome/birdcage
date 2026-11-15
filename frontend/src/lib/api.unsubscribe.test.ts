// onSignedOut returns its unsubscribe: once called, a 401 no longer
// reaches that handler, and it does not remove a later one.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getJSON, onSignedOut } from './api'
import { stubServer } from '../door/testkit'

afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

describe('onSignedOut unsubscribe', () => {
  it('removes the handler it registered', async () => {
    const handler = vi.fn()
    const off = onSignedOut(handler)
    off()
    stubServer({ 'GET /api/canaries': new Response('', { status: 401 }) })
    await getJSON('/api/canaries').catch(() => {})
    expect(handler).not.toHaveBeenCalled()
  })

  it('leaves a handler registered after it in place', async () => {
    const first = vi.fn()
    const second = vi.fn()
    const off = onSignedOut(first)
    onSignedOut(second)
    off()
    stubServer({ 'GET /api/canaries': new Response('', { status: 401 }) })
    await getJSON('/api/canaries').catch(() => {})
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)
  })
})
