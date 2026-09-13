// gen.py's prose spells out small counts ("nine minutes", "the other
// three are fine") and keeps compact labels ("9 m", "7x", "221x") as
// digits. ADR-0004 and issue #38 both call this "numbers under ten in
// words in prose" -- these two helpers are that rule.
const ONES = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine']
const TEENS = [
  'ten',
  'eleven',
  'twelve',
  'thirteen',
  'fourteen',
  'fifteen',
  'sixteen',
  'seventeen',
  'eighteen',
  'nineteen',
]
const TENS = ['', '', 'twenty', 'thirty', 'forty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety']

/** Full spelling for 0-99 (falls back to digits above that). Used where the
 * concept always spells a count out regardless of size, e.g. the footer's
 * "twenty-three quiet days" (issue #38). */
export function numberToWords(n: number): string {
  if (n < 0 || !Number.isInteger(n)) return String(n)
  if (n < 10) return ONES[n]
  if (n < 20) return TEENS[n - 10]
  if (n < 100) {
    const tens = Math.floor(n / 10)
    const ones = n % 10
    return ones === 0 ? TENS[tens] : `${TENS[tens]}-${ONES[ones]}`
  }
  return String(n)
}

/** Word for n < 10, digits from 10 up -- the general prose rule (e.g. the
 * hero's "23 days" stays digits; "the other three are fine" spells out). */
export function wordOrNumber(n: number): string {
  return n < 10 && n >= 0 && Number.isInteger(n) ? ONES[n] : String(n)
}

export function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return n === 1 ? word : pluralWord
}
