# Batch-a audit record, #249

- Bug bar: the standing rule (severity scale v2), stamped 2026-11-21; no release exceptions.
- Range: e2c69cb (the last audit's marker) to 2f45c68 (frozen tip), about 12,300 changed lines.
- Stages: docs pass, release pass (three stages, with property passes), ruling and sweep, fix batch, fix review, security (four lenses and two property passes) on the fixed head, the security fix's ruling, and its fix review.
- Fixed now, reviewed by a non-author: one High (the security fix; tests first by a different agent) and five Lows. Merged into batch-a by !184.
- After release: #235. Docs: #250.
- Follow-up, 2026-11-22: the intake into dev (!186) failed its live checks. The fixes for #251 (one product fix, tests first by a different agent; the rest test and check fixes), reviewed inline by non-authors, every blocking job green on a draft into dev (pipeline 5166), merged into batch-a by !188.
- Follow-up, 2026-11-23: the next intake run (pipeline 5241) found #253. The fix (one product fix, tests first by a different agent, reviewed inline by a third; plus check fixes), every blocking job green on a draft into dev (pipeline 5261), merged into batch-a by !191.
- Follow-up, 2026-11-24: intake runs 5241, 5260 and 5268 found #254. The fix (one product fix, tests first by a different agent, reviewed inline by a third; plus a check fix and flake records), every blocking job green on a draft into dev (pipeline 5280), merged into batch-a by !194.

Audited-through: d3172f2b50753c8ccbea0998e61fffa7dc340164
