# Batch-b audit record, #231

- Bug bar: the standing rule (severity scale v2), stamped 2026-11-18; no release exceptions.
- Range: 6dcffab (batch-b's merge base with batch-a) to 1ee8ad2 (frozen tip), about 14,200 added lines.
- Stages: docs pass, engines pass (Chromium and Firefox; WebKit cannot start on this host), release pass (three stages), ruling and sweep, fix batch, fix review, security (four lenses) on the fixed head, security ruling, and a fix review of each security fix.
- Fixed now, each with tests first by a different agent and a fix review: A-R3 (High), D-F4, PF4-F1, SEC-5 (Low). Merged into batch-b by !151.
- Before promotion: #234. After release: #235 and #233. Docs: #232.
- Catch-up from dev: !152.

- Coverage follow-up: the A-R3 fix left a shutdown branch untested, so `test:go` failed its coverage minimum on the dev merge. Tests only, eba0dee, reviewed by a non-author agent (one Low test gap, on #235).

- Coverage floor: internal/tlssniff raised from 94 to 98 to match the new tests, 91a8894, reviewed inline by the author (one line).

Audited-through: 91a889443d4359af7dd9a28dff5610dee259a448
