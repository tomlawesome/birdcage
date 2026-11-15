// The QR code on the "Prove it works" screen (issue #8): the otpauth uri
// an authenticator app scans. The pattern comes from qrcode-generator
// (owner approval 29a, 2026-11-15, on #8) until gauntlet serves it
// itself; docs/design/sign-in-screens.md, "door/qr.ts".
import qrcode from 'qrcode-generator'

/** The QR code of `text` at error-correction level M, `true` for a dark
 * module: square, side 21 + 4k, the smallest version that holds it. */
export function qrMatrix(text: string): boolean[][] {
  const qr = qrcode(0, 'M')
  qr.addData(text, 'Byte')
  qr.make()
  const n = qr.getModuleCount()
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)))
}

/** Fills the canvas white, then draws the code of `text` edge to edge in
 * the door's ink, one rect per dark module. Module edges are rounded to
 * whole pixels so neighbouring modules meet without a seam. */
export function drawQR(canvas: HTMLCanvasElement, text: string): void {
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  const m = qrMatrix(text)
  const n = m.length
  const { width: w, height: h } = canvas
  ctx.fillStyle = '#ffffff'
  ctx.fillRect(0, 0, w, h)
  ctx.fillStyle = '#06080e'
  const xs = Array.from({ length: n + 1 }, (_, i) => Math.round((i * w) / n))
  const ys = Array.from({ length: n + 1 }, (_, i) => Math.round((i * h) / n))
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (m[r][c]) ctx.fillRect(xs[c], ys[r], xs[c + 1] - xs[c], ys[r + 1] - ys[r])
    }
  }
}
