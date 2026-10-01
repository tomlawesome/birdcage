#!/usr/bin/env node
// Proves getFreePorts never returns the same port twice in one call
// (#159). The one-at-a-time allocator it replaced repeated a port 3 to 11
// times in 20,000 draws of three when measured locally, so 100,000 draws
// (about ten seconds) should all but certainly catch a regression.
import { getFreePorts } from './ports.mjs'

const DRAWS = 100000
let repeats = 0
for (let i = 0; i < DRAWS; i += 1) {
  const ports = await getFreePorts(3)
  if (new Set(ports).size !== ports.length) repeats += 1
}
if (repeats > 0) {
  console.log(`FAIL - ${repeats} of ${DRAWS} draws of three ports repeated a port`)
  process.exit(1)
}
console.log(`ok - ${DRAWS} draws of three ports, no port repeated within a draw`)
