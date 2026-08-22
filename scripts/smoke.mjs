/**
 * Post-build smoke check.
 *
 * `tsx` strips types without checking them and the test suite never touches
 * `dist/`, so both the `exports` map and the built entries can break with the
 * suite green. This loads what a consumer loads.
 */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const RESOLVERS = ['webBotAuth', 'signatureAgent', 'bearerClaims', 'userAgentPattern']
const CONTRACT = ['sendProblem', 'buildProblem', 'PROBLEM_TYPES', 'DEFAULT_PROBLEM_BASE_URI']

function check(label, module) {
  assert.equal(typeof module.default, 'function', `${label}: default export is the plugin`)
  for (const name of [...RESOLVERS, ...CONTRACT]) {
    assert.notEqual(module[name], undefined, `${label}: missing named export "${name}"`)
  }
  for (const name of RESOLVERS) {
    assert.equal(typeof module[name], 'function', `${label}: "${name}" is not callable`)
  }
  assert.equal(Object.keys(module.PROBLEM_TYPES).length, 8, `${label}: eight problem types`)
  console.log(`${label}: default export + ${RESOLVERS.length} resolvers + contract OK`)
}

const esm = await import('../dist/index.js')
check('dist/index.js  (ESM)', esm)

const require = createRequire(import.meta.url)
const cjs = require('../dist/index.cjs')
check('dist/index.cjs (CJS)', cjs)

// Boot the built plugin for real, not just import it.
const { default: Fastify } = await import('fastify')
const app = Fastify()
await app.register(esm.default, { identify: () => null, applyTo: 'all' })
app.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
const response = await app.inject({ method: 'GET', url: '/x' })
assert.equal(response.statusCode, 401, 'built plugin denies an unidentified caller')
assert.equal(response.headers['content-type'], 'application/problem+json')
assert.equal(JSON.parse(response.body).title, 'Agent identity required')
await app.close()
console.log('dist boot: 401 application/problem+json OK')
