import { describe, expect, it } from 'vitest'
import { portForService } from './ports'

// ports is a display string like "ssh 22 · http 80 · smb 445" (Canary.ports).
// The only real decision here: is the requested service in the list (return
// its port) or not (return null, the fallback callers use to show nothing).

describe('portForService', () => {
  const ports = 'ssh 22 · http 80 · smb 445'

  it('finds the service when it is first in the list', () => {
    expect(portForService(ports, 'ssh')).toBe('22')
  })

  it('finds the service when it is later in the list', () => {
    expect(portForService(ports, 'smb')).toBe('445')
  })

  it('returns null when the service is not present', () => {
    expect(portForService(ports, 'ftp')).toBeNull()
  })
})
