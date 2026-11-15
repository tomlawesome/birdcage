// The QR square on the "Prove it works" screen (issue #8). Drawing a real
// QR code needs a library birdcage has not approved, and the choice is
// the owner's (docs/design/sign-in-screens.md, "Open"). Until then the
// screen shows the secret only: HAS_QR is false, so no canvas is drawn,
// and drawQR draws nothing. Choosing a library means implementing drawQR
// and setting HAS_QR to true; nothing else on the screen changes.

/** Whether drawQR can draw a code yet. */
export const HAS_QR = false

/** Draws the otpauth uri as a QR code on canvas. A no-op until the
 * owner chooses how QR codes are drawn. */
export function drawQR(canvas: HTMLCanvasElement, uri: string): void {
  void canvas
  void uri
}
