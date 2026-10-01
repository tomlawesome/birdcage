// Free loopback ports for the smoke journey's listeners (#159).
//
// Asking for one port at a time -- bind port 0, read it, close, repeat --
// can hand the same port out twice: once a listener is closed its port is
// free again, and the kernel may give it to the very next bind. That
// happened in CI (pipeline 1867: dashboard and ingest both on one port,
// "address already in use"). Holding every listener open until all the
// ports have been read makes a repeat impossible within one call.
//
// A port can still be taken by some other process between close and
// birdcage's own bind; nothing short of passing the socket itself avoids
// that, and it is far rarer than reusing our own freed port.
import { createServer } from 'node:net'

function listenOnFreePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => resolve(srv))
  })
}

function close(srv) {
  return new Promise((resolve) => srv.close(() => resolve()))
}

export async function getFreePorts(count) {
  const servers = []
  try {
    for (let i = 0; i < count; i += 1) servers.push(await listenOnFreePort())
    return servers.map((srv) => srv.address().port)
  } finally {
    await Promise.all(servers.map(close))
  }
}
