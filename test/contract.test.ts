import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify from 'fastify'

import agentPolicy, { PROBLEM_CONTENT_TYPE } from '../src/index.ts'

const DENIAL_TYPE = 'https://github.com/umxr/fastify-agent-policy/problems/agent_identity_required'

test('a route response schema does not reshape the problem document', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => null, applyTo: 'all' })

  app.get(
    '/policed',
    {
      config: { agent: { risk: 'read' } },
      schema: {
        response: {
          // A route that documents its own 401 envelope. Without the reply
          // serializer the denial is serialized through this schema and
          // arrives as `{}` while the content type still claims
          // application/problem+json.
          401: {
            type: 'object',
            properties: { error: { type: 'string' } },
            additionalProperties: false,
          },
          200: { type: 'object', properties: { ok: { type: 'boolean' } } },
        },
      },
    },
    async () => ({ ok: true }),
  )
  await app.ready()

  const response = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(response.statusCode, 401)
  assert.equal(response.headers['content-type'], PROBLEM_CONTENT_TYPE)

  const body = response.json()
  assert.equal(body.type, DENIAL_TYPE)
  assert.equal(body.title, 'Agent identity required')
  assert.equal(body.status, 401)
  assert.equal(body.retryable, false)
  assert.equal(typeof body.detail, 'string')

  await app.close()
})

test('the route response schema still applies to a successful response', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => ({ id: 'https://a.example' }) })
  app.get(
    '/policed',
    {
      config: { agent: { risk: 'read' } },
      schema: {
        response: {
          200: {
            type: 'object',
            properties: { ok: { type: 'boolean' } },
            additionalProperties: false,
          },
        },
      },
    },
    async () => ({ ok: true, secret: 'stripped' }),
  )
  await app.ready()

  const response = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(response.statusCode, 200)
  // The reply serializer is only installed on a denial, so the route's own
  // schema is untouched on the happy path.
  assert.deepEqual(response.json(), { ok: true })
  await app.close()
})

test('the denial precedes body parsing and schema validation', async () => {
  const app = Fastify()
  let handlerRuns = 0
  await app.register(agentPolicy, { identify: () => null, applyTo: 'all' })

  app.post(
    '/orders',
    {
      config: { agent: { risk: 'write' } },
      schema: {
        body: {
          type: 'object',
          required: ['amount'],
          properties: { amount: { type: 'number' } },
        },
      },
    },
    async () => {
      handlerRuns += 1
      return { ok: true }
    },
  )
  await app.ready()

  // The body is invalid for the route schema. The denial must still win --
  // in `preHandler` this arrived as `400 FST_ERR_VALIDATION` in
  // application/json, which is not the documented contract.
  const response = await app.inject({
    method: 'POST',
    url: '/orders',
    payload: { nope: true },
  })

  assert.equal(response.statusCode, 401)
  assert.equal(response.headers['content-type'], PROBLEM_CONTENT_TYPE)
  assert.equal(response.json().type, DENIAL_TYPE)
  assert.equal(handlerRuns, 0)
  await app.close()
})

test('an unparseable body is also denied before it is parsed', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => null, applyTo: 'all' })
  app.post('/orders', { config: { agent: { risk: 'write' } } }, async () => ({ ok: true }))
  await app.ready()

  const response = await app.inject({
    method: 'POST',
    url: '/orders',
    headers: { 'content-type': 'application/json' },
    payload: '{ this is not json',
  })

  assert.equal(response.statusCode, 401)
  assert.equal(response.json().type, DENIAL_TYPE)
  await app.close()
})

test('an identified caller still gets normal validation', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify: () => ({ id: 'https://a.example' }),
    applyTo: 'all',
  })
  app.post(
    '/orders',
    {
      config: { agent: { risk: 'write' } },
      schema: {
        body: { type: 'object', required: ['amount'], properties: { amount: { type: 'number' } } },
      },
    },
    async () => ({ ok: true }),
  )
  await app.ready()

  const bad = await app.inject({ method: 'POST', url: '/orders', payload: { nope: true } })
  assert.equal(bad.statusCode, 400)
  assert.equal(bad.json().code, 'FST_ERR_VALIDATION')

  const good = await app.inject({ method: 'POST', url: '/orders', payload: { amount: 5 } })
  assert.equal(good.statusCode, 200)
  await app.close()
})
