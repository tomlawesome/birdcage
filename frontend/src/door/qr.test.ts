import { describe, expect, it, vi } from 'vitest'
import { drawQR, qrMatrix } from './qr'

const URI = 'otpauth://totp/birdcage:ada?secret=AAAAAAAAAAAAAAAA&issuer=birdcage'
const OTHER = 'otpauth://totp/birdcage:bob?secret=BBBBBBBBBBBBBBBB&issuer=birdcage'

function isFinder(m: boolean[][], r0: number, c0: number): boolean {
  for (let r = 0; r < 7; r++) {
    for (let c = 0; c < 7; c++) {
      const edge = r === 0 || r === 6 || c === 0 || c === 6
      const centre = r >= 2 && r <= 4 && c >= 2 && c <= 4
      if (m[r0 + r][c0 + c] !== (edge || centre)) return false
    }
  }
  return true
}

describe('qrMatrix', () => {
  it('is square with side 21 + 4k', () => {
    for (const text of [URI, OTHER, 'a']) {
      const m = qrMatrix(text)
      expect(m.length).toBeGreaterThanOrEqual(21)
      expect((m.length - 21) % 4).toBe(0)
      for (const row of m) expect(row.length).toBe(m.length)
    }
  })
  it('gives an equal matrix for the same text', () => {
    expect(qrMatrix(URI)).toEqual(qrMatrix(URI))
  })
  it('gives different matrices for different otpauth URIs', () => {
    expect(qrMatrix(URI)).not.toEqual(qrMatrix(OTHER))
  })
  it('has the standard finder pattern in three corners', () => {
    const m = qrMatrix(URI)
    const n = m.length
    expect(isFinder(m, 0, 0)).toBe(true)
    expect(isFinder(m, 0, n - 7)).toBe(true)
    expect(isFinder(m, n - 7, 0)).toBe(true)
  })
  it('has no finder pattern in the bottom right corner', () => {
    const m = qrMatrix(URI)
    const n = m.length
    expect(isFinder(m, n - 7, n - 7)).toBe(false)
  })
})

describe('drawQR', () => {
  function run() {
    const calls: { style: unknown; x: number; y: number; w: number; h: number }[] = []
    const ctx = {
      fillStyle: '' as unknown,
      fillRect: vi.fn((x: number, y: number, w: number, h: number) => {
        calls.push({ style: ctx.fillStyle, x, y, w, h })
      }),
    }
    const canvas = { width: 210, height: 210, getContext: vi.fn(() => ctx) }
    drawQR(canvas as unknown as HTMLCanvasElement, URI)
    return { calls, canvas, ctx }
  }
  const isWhite = (s: unknown) => typeof s === 'string' && ['#fff', '#ffffff', 'white'].includes(s.toLowerCase())

  it('first fills the whole canvas white', () => {
    const { calls, canvas } = run()
    expect(calls.length).toBeGreaterThan(0)
    const first = calls[0]
    expect(isWhite(first.style)).toBe(true)
    expect([first.x, first.y, first.w, first.h]).toEqual([0, 0, canvas.width, canvas.height])
  })
  it('calls fillRect once per dark module in #06080e', () => {
    const { calls } = run()
    const dark = qrMatrix(URI).flat().filter(Boolean).length
    const rest = calls.slice(1)
    expect(rest.length).toBe(dark)
    for (const c of rest) expect(String(c.style).toLowerCase()).toBe('#06080e')
  })
  it('keeps every rect inside the canvas', () => {
    const { calls, canvas } = run()
    for (const c of calls) {
      expect(c.x).toBeGreaterThanOrEqual(0)
      expect(c.y).toBeGreaterThanOrEqual(0)
      expect(c.w).toBeGreaterThan(0)
      expect(c.h).toBeGreaterThan(0)
      expect(c.x + c.w).toBeLessThanOrEqual(canvas.width + 1e-6)
      expect(c.y + c.h).toBeLessThanOrEqual(canvas.height + 1e-6)
    }
  })
})
