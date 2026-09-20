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
    },
  },
})
