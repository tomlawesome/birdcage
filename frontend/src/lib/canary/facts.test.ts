import { describe, expect, it } from 'vitest'
import { sceneInput } from './fixtures'
import { factRows, upgradeCommandCLI } from './facts'

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

// Issue #54: birdcage's own comparison of the agent's build against its
// own stamped version, shown as a standing fact whenever
// agent_out_of_date is active. The backend is the single source of
// truth for "active" -- `status` or `active_states` -- never a version
// comparison the frontend re-derives itself.
describe('factRows: agent_out_of_date (issue #54)', () => {
  it('names the running and current versions, dropping the commit suffix from both', () => {
    const rows = factRows(sceneInput('agentOutOfDate'))
    // The plain "agent" fact still names the full build, commit and
    // all (unchanged, pre-#54 behaviour) -- only the new "upgrade" row
    // is required to drop it.
    expect(rows.find((r) => r.label === 'upgrade')?.value).toBe('runs 0.1.0 · current 0.1.1')
  })

  it('offers the command that prints the upgrade command, never a command itself', () => {
    const input = sceneInput('agentOutOfDate')
    const rows = factRows(input)
    const row = rows.find((r) => r.label === 'run this')
    expect(row?.code).toBe('birdcage agent upgrade-command canary-iot')
    expect(row?.value).toBe('')
    expect(rows.find((r) => r.label === 'where')?.value).toBe(
      "on the birdcage host — it prints this agent's upgrade command, single use and valid for 15 minutes; paste all of it on the agent's host in one go",
    )
    expect(rows.some((r) => (r.code ?? '').includes('docker'))).toBe(false)
  })

  it('falls back to a docs pointer when this birdcage cannot print one', () => {
    const input = sceneInput('agentOutOfDate')
    input.page.canary.upgrade_available = false
    const rows = factRows(input)
    const row = rows.find((r) => r.label === 'run this')
    expect(row?.code).toBeUndefined()
    expect(row?.value).toBe('not available from this birdcage — see docs/enrolment.md, "Upgrading a canary"')
    expect(rows.some((r) => r.label === 'where')).toBe(false)
  })

  it('never hands the copy button an id a shell would read as more than a word', () => {
    const input = sceneInput('agentOutOfDate')
    input.page.canary.id = 'canary-iot; rm -rf /'
    expect(factRows(input).find((r) => r.label === 'run this')?.code).toBeUndefined()
    expect(upgradeCommandCLI({ id: 'a$(x)', upgrade_available: true })).toBeNull()
    expect(upgradeCommandCLI({ id: '0f3a9c', upgrade_available: true })).toBe('birdcage agent upgrade-command 0f3a9c')
  })

  it('shows the rows when active_states names it, even though a worse state holds `status`', () => {
    const input = sceneInput('agentOutOfDate')
    input.page.canary.status = 'silent'
    input.page.canary.active_states = ['silent', 'agent_out_of_date']
    const rows = factRows(input)
    expect(rows.find((r) => r.label === 'upgrade')?.value).toBe('runs 0.1.0 · current 0.1.1')
    expect(rows.find((r) => r.label === 'run this')?.code).toBe('birdcage agent upgrade-command canary-iot')
  })

  it('says nothing when neither `status` nor `active_states` names it, even if the versions differ', () => {
    const input = sceneInput('agentOutOfDate')
    input.page.canary.status = 'ok'
    input.page.canary.active_states = ['ok']
    expect(factRows(input).some((r) => r.label === 'upgrade' || r.label === 'run this')).toBe(false)
  })
})

// Issue #54 (owner, 2026-09-27): the upgrade window, with its end.
describe('factRows: upgrade_in_progress (issue #54)', () => {
  it('names when the window ends', () => {
    const rows = factRows(sceneInput('upgradeInProgress'))
    expect(rows.find((r) => r.label === 'upgrade window')?.value).toBe(
      'open until sun 20 sep 09:18 — the old agent has until then to go offline',
    )
    expect(rows.some((r) => r.label === 'upgrade' || r.label === 'run this')).toBe(false)
  })

  it('says nothing about a window once the state is gone', () => {
    const input = sceneInput('upgradeInProgress')
    input.page.canary.status = 'ok'
    input.page.canary.active_states = []
    expect(factRows(input).some((r) => r.label === 'upgrade window')).toBe(false)
  })
})
