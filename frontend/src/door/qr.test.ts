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

// A reader for the matrix, written from ISO/IEC 18004 rather than from
// qrcode-generator, so the tests can check the code says what it must:
// the format bits, the unmasked codewords, the Reed-Solomon check bytes
// and the byte-mode payload. Covers level M, versions 1-10 -- every
// otpauth URI the door shows fits.
const M_BLOCKS: Record<number, [count: number, total: number, data: number][]> = {
  1: [[1, 26, 16]],
  2: [[1, 44, 28]],
  3: [[1, 70, 44]],
  4: [[2, 50, 32]],
  5: [[2, 67, 43]],
  6: [[4, 43, 27]],
  7: [[4, 49, 31]],
  8: [[2, 60, 38], [2, 61, 39]],
  9: [[3, 58, 36], [2, 59, 37]],
  10: [[4, 69, 43], [1, 70, 44]],
}
const ALIGN: Record<number, number[]> = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
  7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}
const MASKS: ((i: number, j: number) => boolean)[] = [
  (i, j) => (i + j) % 2 === 0,
  (i) => i % 2 === 0,
  (_, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i * j) % 3) + ((i + j) % 2)) % 2 === 0,
]

// GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1.
const EXP: number[] = []
const LOG: number[] = []
for (let i = 0, x = 1; i < 255; i++, x = (x << 1) ^ (x & 0x80 ? 0x11d : 0)) {
  EXP[i] = x
  LOG[x] = i
}
const gmul = (a: number, b: number) => (a && b ? EXP[(LOG[a] + LOG[b]) % 255] : 0)
function rsCheck(data: number[], n: number): number[] {
  let g = [1]
  for (let i = 0; i < n; i++) {
    const next = new Array(g.length + 1).fill(0)
    g.forEach((c, k) => {
      next[k] ^= c
      next[k + 1] ^= gmul(c, EXP[i])
    })
    g = next
  }
  const rem = [...data, ...new Array(n).fill(0)]
  for (let i = 0; i < data.length; i++) {
    const f = rem[i]
    if (f) g.forEach((c, k) => (rem[i + k] ^= gmul(c, f)))
  }
  return rem.slice(data.length)
}

// The 15 format bits for level M (00) and a mask, BCH-coded and masked.
function formatBits(mask: number): number {
  const d = (0b00 << 3) | mask
  let r = d << 10
  for (let b = 14; b >= 10; b--) if (r & (1 << b)) r ^= 0x537 << (b - 10)
  return ((d << 10) | r) ^ 0x5412
}

function readQR(m: boolean[][]): { text: string; mask: number; rsOK: boolean } {
  const n = m.length
  const version = (n - 17) / 4
  const blocks = M_BLOCKS[version]
  if (!blocks) throw new Error(`version ${version} is outside the reader's table`)

  // Format bits, the copy down column 8 then along the bottom of it.
  let fmt = 0
  for (let i = 0; i < 15; i++) {
    const r = i < 6 ? i : i < 8 ? i + 1 : n - 15 + i
    if (m[r][8]) fmt |= 1 << i
  }
  const mask = MASKS.findIndex((_, k) => formatBits(k) === fmt)
  if (mask < 0) throw new Error(`format bits ${fmt.toString(2)} are not level M with any mask`)

  const fn = Array.from({ length: n }, () => new Array<boolean>(n).fill(false))
  const mark = (r0: number, c0: number, h: number, w: number) => {
    for (let r = r0; r < r0 + h; r++) for (let c = c0; c < c0 + w; c++) fn[r][c] = true
  }
  mark(0, 0, 9, 9)
  mark(0, n - 8, 9, 8)
  mark(n - 8, 0, 8, 9)
  mark(6, 0, 1, n)
  mark(0, 6, n, 1)
  const pos = ALIGN[version]
  for (const r of pos) {
    for (const c of pos) {
      const last = pos[pos.length - 1]
      if ((r === 6 && c === 6) || (r === 6 && c === last) || (r === last && c === 6)) continue
      mark(r - 2, c - 2, 5, 5)
    }
  }
  if (version >= 7) {
    mark(0, n - 11, 6, 3)
    mark(n - 11, 0, 3, 6)
  }

  const bits: number[] = []
  let up = true
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let v = 0; v < n; v++) {
      const i = up ? n - 1 - v : v
      for (const j of [right, right - 1]) if (!fn[i][j]) bits.push(m[i][j] !== MASKS[mask](i, j) ? 1 : 0)
    }
    up = !up
  }
  const words: number[] = []
  for (let k = 0; k + 8 <= bits.length; k += 8) words.push(bits.slice(k, k + 8).reduce((a, b) => (a << 1) | b, 0))

  // Undo the interleaving: data codewords first, then check bytes.
  const shapes = blocks.flatMap(([count, total, data]) => new Array(count).fill([total, data] as const))
  const data: number[][] = shapes.map(() => [])
  const ec: number[][] = shapes.map(() => [])
  let w = 0
  for (let i = 0; i < Math.max(...shapes.map((s) => s[1])); i++) shapes.forEach(([, d], b) => i < d && data[b].push(words[w++]))
  for (let i = 0; i < shapes[0][0] - shapes[0][1]; i++) shapes.forEach((_, b) => ec[b].push(words[w++]))
  const rsOK = shapes.every(([t, d], b) => JSON.stringify(rsCheck(data[b], t - d)) === JSON.stringify(ec[b]))

  const stream = data.flat().flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((k) => (byte >> k) & 1))
  let at = 0
  const take = (k: number) => stream.slice(at, (at += k)).reduce((a, b) => (a << 1) | b, 0)
  const mode = take(4)
  if (mode !== 0b0100) throw new Error(`mode ${mode.toString(2)} is not byte mode`)
  const len = take(version < 10 ? 8 : 16)
  const bytes = Uint8Array.from({ length: len }, () => take(8))
  return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), mask, rsOK }
}

describe('qrMatrix encodes the text', () => {
  const LONG = 'otpauth://totp/birdcage:ada.lovelace?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=birdcage&digits=6&period=30'
  for (const text of [URI, OTHER, LONG, 'a']) {
    it(`reads back as ${JSON.stringify(text.slice(0, 40))}… with valid check bytes`, () => {
      const got = readQR(qrMatrix(text))
      expect(got.text).toBe(text)
      expect(got.rsOK).toBe(true)
    })
  }
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
