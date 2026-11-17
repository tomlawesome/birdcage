/** The write actions -- "run the self-test now" and "mark as
 * maintenance" -- have no route behind them yet (#227). Until they do,
 * they are hidden everywhere (#228) rather than offered and silently
 * doing nothing. Flip this to true when #227 lands. */
export const WRITE_ROUTES_LIVE = false

/** The read-only pointers -- "lookback in mikroview" and "raw lines" --
 * have no target yet: birdcage has no mikroview address, and the
 * lookback is ADR-0003's planned integration, not built. Until they
 * do, they are hidden everywhere (#229) rather than offered as pills
 * that silently do nothing. Flip this to true when ADR-0003's lookback
 * link lands. */
export const MIKROVIEW_LINKS_LIVE = false
