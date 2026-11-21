# Batch-a audit record, #249

- Bug bar: the standing rule (severity scale v2), stamped 2026-11-21; no release exceptions.
- Range: e2c69cb (the last audit's marker) to 2f45c68 (frozen tip), about 12,300 changed lines.
- Stages: docs pass, release pass (three stages, with property passes), ruling and sweep, fix batch, fix review, security (four lenses and two property passes) on the fixed head, the security fix's ruling, and its fix review.
- Fixed now, reviewed by a non-author: one High (the security fix; tests first by a different agent) and five Lows. Merged into batch-a by !184.
- After release: #235. Docs: #250.

Audited-through: f3e2bf588a46fbbcee2b17711ee9ac6944296735
