// compare:door's harness: mounts the built door with the session the
// compare script answers at /api/auth/session, its bars frozen at ?t=.
// ?shell=<url> puts an image behind it, as the mock-up's dashboard
// stands behind its session-expired screen.
import { mount } from 'svelte'
import '../src/app.css'
import Door from '../src/door/Door.svelte'
import { readSession } from '../src/lib/auth'

const q = new URLSearchParams(location.search)
const shell = q.get('shell')
if (shell) {
  const img = document.createElement('img')
  img.src = shell
  img.alt = ''
  img.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;object-fit:cover;object-position:left top'
  document.body.prepend(img)
}

const session = await readSession()
mount(Door, {
  target: document.getElementById('app')!,
  props: { session, frozenAt: Number(q.get('t') ?? 0), onenter: () => {} },
})
document.body.dataset.ready = '1'
