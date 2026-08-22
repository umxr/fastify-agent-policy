import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyError } from 'fastify'

import agentPolicy from '../src/index.ts'

test('a host root setErrorHandler does not touch a denial', async () => {
  const app = Fastify()
  let handlerCalls = 0

  // A typical host handler: it rewrites every error into the app's own
  // envelope, with `application/json`. Denials must not pass through it.
  app.setErrorHandler((error: FastifyError, _request, reply) => {
    handlerCalls += 1
    reply.code(error.statusCode ?? 500).send({ ok: false, message: error.message })
  })

  await app.register(agentPolicy, { identify: () => null, applyTo: 'all' })
  app.get('/policed', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.get('/boom', async () => {
    throw new Error('kaboom')
  })
  await app.ready()

  const denied = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(denied.statusCode, 401)
  assert.equal(denied.headers['content-type'], 'application/problem+json')
  assert.equal(
    denied.json().type,
    'https://github.com/umxr/fastify-agent-policy/problems/agent_identity_required',
  )
  assert.equal(handlerCalls, 0, 'the denial bypassed the host error handler')

  // The host handler still owns real errors.
  const boom = await app.inject({ method: 'GET', url: '/boom' })
  assert.equal(boom.statusCode, 500)
  assert.deepEqual(boom.json(), { ok: false, message: 'kaboom' })
  assert.equal(handlerCalls, 1)

  await app.close()
})

test('the plugin never installs an error handler of its own', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => null })
  app.get('/boom', async () => {
    throw new Error('kaboom')
  })
  await app.ready()

  // Fastify's own default handler formats this, proving nothing intercepted it.
  const response = await app.inject({ method: 'GET', url: '/boom' })
  assert.equal(response.statusCode, 500)
  assert.equal(response.json().error, 'Internal Server Error')
  await app.close()
})
