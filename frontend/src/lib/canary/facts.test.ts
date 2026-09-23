import { describe, expect, it } from 'vitest'
import { sceneInput } from './fixtures'
import { factRows } from './facts'

const rows = (scene: Parameters<typeof sceneInput>[0]) =>
  Object.fromEntries(factRows(sceneInput(scene)).map((r) => [r.label, r.value]))

describe('factRows', () => {
  it('names what birdcage knows about the canary', () => {
    expect(rows('quiet')).toEqual({
      kind: 'honeypot',
      lane: 'iot',
      address: '10.0.30.9',
      listening: 'telnet 23 · ssh 22 · smb 445',
      'lure only': 'portscan',
      heartbeat: 'every minute',
      'self-test': 'daily · 04:00',
      enrolled: 'wed 12 aug 09:41',
      agent: 'mockingbird 0.4.1',
      token: 'rotated thu 3 sep · next in 25 h',
    })
  })

  it('the lane carries the canary\'s own colour, as its name does everywhere else', () => {
    expect(factRows(sceneInput('quiet')).find((r) => r.label === 'lane')?.accent).toBe(true)
  })

  it('a fact birdcage does not know is left out, not guessed at', () => {
    const input = sceneInput('quiet')
    delete input.page.facts.address
    delete input.page.facts.agent_version
    delete input.page.facts.token_rotated_at
    const labels = factRows(input).map((r) => r.label)
    expect(labels).not.toContain('address')
    expect(labels).not.toContain('agent')
    expect(labels).not.toContain('token')
  })

  it('a switched-off self-test says off rather than a schedule it will not keep', () => {
    const input = sceneInput('quiet')
    input.page.facts.self_test_enabled = false
    expect(factRows(input).find((r) => r.label === 'self-test')?.value).toBe('off')
  })

  it('the rotation countdown stays in hours up to two days -- "next in 25 h" answers "is it tonight?"', () => {
    const input = sceneInput('quiet')
    input.page.facts.token_rotates_at = '2026-09-09T22:04:31Z'
    expect(factRows(input).find((r) => r.label === 'token')?.value).toBe('rotated thu 3 sep · next in 4 d')
  })
})
