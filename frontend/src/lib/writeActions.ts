/** The write actions -- "run the self-test now" and "mark as
 * maintenance" -- have no route behind them yet (#227). Until they do,
 * they are hidden everywhere (#228) rather than offered and silently
 * doing nothing. Flip this to true when #227 lands. */
export const WRITE_ROUTES_LIVE = false
