// A TLS 1.3 + HTTP/2 mutual-authentication server for ClientTlsProbeTests: what the machine listener is, but made by Node, so a platform whose .NET has no server-side TLS 1.3 (macOS)
// can still test its CLIENT (the TLS 1.3 backend, presenting a client certificate, strict validation of the server certificate). It is a test tool: it answers every request with an empty JSON
// object and prints one JSON line per event (what was negotiated, whether the client certificate verified, which request came), so the test can check what really happened on the wire.
// Usage: node server.mjs <server-cert.pem> <server-key.pem> <client-ca.pem>
import http2 from 'node:http2'
import fs from 'node:fs'

const [, , certPath, keyPath, caPath] = process.argv
const log = (event) => console.log(JSON.stringify(event))

const server = http2.createSecureServer({
  cert: fs.readFileSync(certPath),
  key: fs.readFileSync(keyPath),
  ca: fs.readFileSync(caPath), // the only root a client certificate may chain to
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.3',
  maxVersion: 'TLSv1.3',
  ALPNProtocols: ['h2'],
  allowHTTP1: false,
})

server.on('secureConnection', (socket) => {
  const peer = socket.getPeerCertificate()
  log({ event: 'connection', protocol: socket.getProtocol(), alpn: socket.alpnProtocol, authorized: socket.authorized, san: peer?.subjectaltname ?? '' })
})
server.on('tlsClientError', (error) => log({ event: 'tlsClientError', code: error.code ?? '' }))
server.on('stream', (stream, headers) => {
  log({ event: 'request', method: headers[':method'], path: headers[':path'] })
  stream.respond({ ':status': 200, 'content-type': 'application/json; charset=utf-8' })
  stream.end('{}')
})
server.listen(0, '127.0.0.1', () => log({ event: 'listening', port: server.address().port }))
