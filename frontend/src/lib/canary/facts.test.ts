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

  it('lists the bait names the poisoner detector is asking for', () => {
    const input = sceneInput('quiet')
    input.page.facts.poisoner_names = 'old-fs-01,printer-7,wpad'
    expect(factRows(input).find((r) => r.label === 'bait names')?.value).toBe(
      'old-fs-01 · printer-7 · wpad',
    )
  })

  it('leaves the bait names out when the canary reports none', () => {
    // The detector off, an older agent, or a kind that is not a honeypot --
    // all ordinary, and none of them a row saying nothing.
    const input = sceneInput('quiet')
    delete input.page.facts.poisoner_names
    expect(factRows(input).map((r) => r.label)).not.toContain('bait names')
    input.page.facts.poisoner_names = ''
    expect(factRows(input).map((r) => r.label)).not.toContain('bait names')
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

  it('renders a confirmed setting with the ● mark and an unconfirmed one with ○', () => {
    const input = sceneInput('quiet')
    input.page.facts.settings = [
      { key: 'segment_profile', value: 'off', version: 2, updated_at: '2026-09-01T00:00:00Z', confirmed: false },
      { key: 'pace_floor', value: '2h', version: 1, updated_at: '2026-09-01T00:00:00Z', confirmed: true },
    ]
    const found = factRows(input)
    expect(found.find((r) => r.label === 'segment profile')?.value).toBe('off · ○ not yet confirmed')
    expect(found.find((r) => r.label === 'pace floor')?.value).toBe('2h · ● confirmed')
  })

  it('shows no settings rows for a canary nothing has ever been pushed to', () => {
    const input = sceneInput('quiet')
    delete input.page.facts.settings
    expect(factRows(input).some((r) => r.value.includes('confirmed'))).toBe(false)
  })
})
