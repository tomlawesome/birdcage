// Pin the suite's timezone before anything formats a date -- the
// fixtures' timestamps are all UTC (see src/dev/fixtures), and a test
// asserting on a rendered clock string must agree with CI's UTC
// container rather than whatever zone the machine running it is in.
process.env.TZ = 'UTC'

import { svelte } from '@sveltejs/vite-plugin-svelte'
import { svelteTesting } from '@testing-library/svelte/vite'
import { defineConfig } from 'vitest/config'

// Deliberately separate from vite.config.ts: running vitest never needs
// the dev proxy, and app builds are never at risk of picking up
// test-only config by accident.
export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.{test,spec}.{ts,js}'],
    // Coverage (#74). The v8 provider reads the coverage V8 already
    // collects, rather than rewriting the source the way the istanbul
    // provider does, so what is measured is what actually ran.
    //
    // `include` is what makes an untested file visible: every file it
    // matches is reported whether or not a test imported it, so a
    // component nobody tests reads as nought per cent rather than not
    // appearing. That is the gap worth seeing. (Older vitest needed
    // `all: true` for this; v5 removed the option and does it by
    // default, and passing it is now a type error.)
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,svelte}'],
      exclude: [
        // Fixtures and the dev-only seed data are test input, not
        // shipped behaviour.
        'src/dev/**',
        // The mount point: three lines of bootstrap with nothing to
        // assert that the smoke journey does not already prove.
        'src/main.ts',
        'src/**/*.{test,spec}.{ts,js}',
      ],
      // `text` for a human reading the job log, `cobertura` because
      // GitLab reads that to show coverage on the merge request diff,
      // and `json-summary` so a threshold check can read the totals
      // without parsing the table.
      reporter: ['text', 'cobertura', 'json-summary'],
      reportsDirectory: './coverage',
      // A ratchet, not a target (#74). The owner's policy is a 70-85%
      // band everywhere, deliberately not higher -- "we must be sensible
      // and not chase the dragon", 2026-09-20.
      //
      // These numbers are today's measurement rounded down, NOT 70.
      // Setting the band as the threshold would turn the build red on
      // code nobody touched, and a check that is red on arrival is a
      // check people switch off -- the same failure mode
      // scripts/ci-e2e-guard.py exists to prevent.
      //
      // So: coverage cannot fall, and each floor is RAISED as its gap
      // closes. Never lowered. Branches at 60 is the known debt and the
      // one that matters most here -- a branch is a decision the
      // dashboard makes about what to tell the operator, and the
      // safety-critical standards (DO-178C, IEC 61508) ask for decision
      // coverage rather than a line percentage. Raising that one to 70
      // is the next piece of work, not a number to set now.
      // Raised 2026-09-20 from 73/60/77/81 after ports.ts and
      // eventRow.ts gained real tests -- the ratchet working as intended.
      thresholds: {
        statements: 77,
        branches: 65,
        functions: 80,
        lines: 87,
      },
    },
  },
})
