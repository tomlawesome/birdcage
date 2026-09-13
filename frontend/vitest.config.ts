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
  },
})
