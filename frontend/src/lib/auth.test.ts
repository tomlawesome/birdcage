import { afterEach, describe, expect, it, vi } from 'vitest'
import { doorFor, readSession } from './auth'
import { jsonReply, session, stubServer } from '../door/testkit'

describe('doorFor: one case per rule', () => {
  it('setupRequired -> firstrun', () => {
    expect(doorFor(session({ setupRequired: true }))).toBe('firstrun')
  })
  it('authenticated and mustChangePassword -> newpassword', () => {
    expect(doorFor(session({ authenticated: true, mustChangePassword: true }))).toBe('newpassword')
  })
  it('authenticated and mustEnrolSecondFactor -> choose', () => {
    expect(doorFor(session({ authenticated: true, mustEnrolSecondFactor: true }))).toBe('choose')
  })
  it('authenticated and mustEnrolPasskey -> choose', () => {
    expect(doorFor(session({ authenticated: true, mustEnrolPasskey: true }))).toBe('choose')
  })
  it('authenticated with nothing owed -> in', () => {
    expect(doorFor(session({ authenticated: true }))).toBe('in')
  })
  it('resumable -> expired', () => {
    expect(doorFor(session({ resumable: true }))).toBe('expired')
  })
  it('otherwise -> signin', () => {
    expect(doorFor(session())).toBe('signin')
  })
})

describe('doorFor: an earlier rule wins over a later one', () => {
  it('setupRequired beats authenticated', () => {
    expect(doorFor(session({ setupRequired: true, authenticated: true }))).toBe('firstrun')
  })
  it('setupRequired beats resumable', () => {
    expect(doorFor(session({ setupRequired: true, resumable: true }))).toBe('firstrun')
  })
  it('mustChangePassword beats mustEnrol*', () => {
    expect(doorFor(session({ authenticated: true, mustChangePassword: true, mustEnrolSecondFactor: true, mustEnrolPasskey: true }))).toBe('newpassword')
  })
  it('choose beats in', () => {
    expect(doorFor(session({ authenticated: true, mustEnrolPasskey: true, resumable: true }))).toBe('choose')
  })
  it('authenticated beats resumable', () => {
    expect(doorFor(session({ authenticated: true, resumable: true }))).toBe('in')
  })
  it('must* flags without authenticated do not count', () => {
    expect(doorFor(session({ mustChangePassword: true, mustEnrolSecondFactor: true, mustEnrolPasskey: true }))).toBe('signin')
    expect(doorFor(session({ mustChangePassword: true, resumable: true }))).toBe('expired')
  })
})

describe('readSession', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('GETs /api/auth/session and returns the parsed body', async () => {
    const s = session({ ssoAvailable: true })
    const server = stubServer({ 'GET /api/auth/session': jsonReply(s) })
    await expect(readSession()).resolves.toEqual(s)
    expect(server.calls).toHaveLength(1)
    expect(server.calls[0].method).toBe('GET')
    expect(server.calls[0].path).toBe('/api/auth/session')
  })
})
