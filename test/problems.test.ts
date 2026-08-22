import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify from 'fastify'

import agentPolicy, {
  DEFAULT_PROBLEM_BASE_URI,
  PROBLEM_TYPES,
  buildProblem,
  isValidProblemBaseUri,
  sendProblem,
  type ProblemExtensions,
  type ProblemKind,
} from '../src/index.ts'

/**
 * The FR8 contract. Seven of these cannot fire yet -- scope, risk-tier,
 * guard, dry-run and confirmation enforcement are later goals -- but the
 * error contract is published now, so it is tested now.
 */
const CONTRACT: Array<[ProblemKind, number, ProblemExtensions]> = [
  ['scope_denied', 403, { requiredScopes: ['orders:refund'], retryable: false }],
  ['risk_tier_blocked', 403, { retryable: false }],
  ['guard_failed', 403, { retryable: false, detail: 'amount exceeds 500' }],
  [
    'confirmation_required',
    409,
    { confirmationToken: 'ct_abc123', expiresIn: 300, retryable: true },
  ],
  ['confirmation_invalid', 409, { retryable: false }],
  ['confirmation_expired', 409, { retryable: true }],
  ['dry_run_unsupported', 400, { retryable: false }],
  ['agent_identity_required', 401, { retryable: false }],
]

test('all eight problem types are defined, frozen and correctly numbered', () => {
  assert.equal(Object.keys(PROBLEM_TYPES).length, 8)
  assert.ok(Object.isFrozen(PROBLEM_TYPES))

  for (const [kind, status] of CONTRACT) {
    const definition = PROBLEM_TYPES[kind]
    assert.ok(definition, `${kind} is missing`)
    assert.equal(definition.slug, kind)
    assert.equal(definition.status, status)
    assert.equal(typeof definition.title, 'string')
    assert.ok(definition.title.length > 0)
    assert.ok(Object.isFrozen(definition))
  }
})

test('buildProblem always emits type, title and status', () => {
  for (const [kind, status] of CONTRACT) {
    const document = buildProblem(kind)
    // An absent `type` means `about:blank` under RFC 9457, so it is never
    // omitted.
    assert.equal(document.type, `${DEFAULT_PROBLEM_BASE_URI}/${kind}`)
    assert.equal(document.title, PROBLEM_TYPES[kind].title)
    assert.equal(document.status, status)
  }
})

test('buildProblem carries extension members and drops undefined ones', () => {
  const document = buildProblem('scope_denied', {
    requiredScopes: ['orders:refund'],
    retryable: false,
    confirmationToken: undefined,
  })
  assert.deepEqual(document.requiredScopes, ['orders:refund'])
  assert.equal(document.retryable, false)
  assert.ok(!('confirmationToken' in document))
})

test('buildProblem refuses to let an extension overwrite type, title or status', () => {
  const document = buildProblem('scope_denied', {
    type: 'https://evil.example/anything',
    title: 'nope',
    status: 200,
  })
  assert.equal(document.type, `${DEFAULT_PROBLEM_BASE_URI}/scope_denied`)
  assert.equal(document.title, PROBLEM_TYPES.scope_denied.title)
  assert.equal(document.status, 403)
})

test('a trailing slash on the base URI is not doubled', () => {
  const document = buildProblem('guard_failed', {}, 'https://errors.example/p/')
  assert.equal(document.type, 'https://errors.example/p/guard_failed')
})

test('sendProblem emits every type with its status, content type and extensions', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => null })

  for (const [kind, , extensions] of CONTRACT) {
    app.get(`/problem/${kind}`, (_request, reply) => sendProblem(reply, kind, extensions))
  }
  await app.ready()

  for (const [kind, status, extensions] of CONTRACT) {
    const response = await app.inject({ method: 'GET', url: `/problem/${kind}` })

    assert.equal(response.statusCode, status, `${kind} status`)
    assert.equal(
      response.headers['content-type'],
      'application/problem+json',
      `${kind} content type`,
    )

    const body = response.json()
    assert.equal(body.type, `${DEFAULT_PROBLEM_BASE_URI}/${kind}`)
    assert.equal(body.title, PROBLEM_TYPES[kind].title)
    assert.equal(body.status, status)
    for (const [member, value] of Object.entries(extensions)) {
      assert.deepEqual(body[member], value, `${kind}.${member}`)
    }
  }

  await app.close()
})

test('problemBaseUri rebases every type URI', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify: () => null,
    applyTo: 'all',
    problemBaseUri: 'https://api.example/errors/agent',
  })
  app.get('/policed', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.get('/manual', (_request, reply) => sendProblem(reply, 'scope_denied'))
  await app.ready()

  const denied = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(
    denied.json().type,
    'https://api.example/errors/agent/agent_identity_required',
  )

  const manual = await app.inject({ method: 'GET', url: '/manual' })
  assert.equal(manual.json().type, 'https://api.example/errors/agent/scope_denied')

  await app.close()
})

test('extension members cannot pollute the prototype chain', () => {
  const extensions = JSON.parse(
    '{"__proto__":{"polluted":true},"constructor":"nope","prototype":"nope","retryable":false}',
  ) as ProblemExtensions

  const document = buildProblem('guard_failed', extensions)

  assert.equal(document.retryable, false)
  assert.ok(!Object.prototype.hasOwnProperty.call(document, '__proto__'))
  assert.ok(!Object.prototype.hasOwnProperty.call(document, 'constructor'))
  assert.ok(!Object.prototype.hasOwnProperty.call(document, 'prototype'))
  assert.equal(Object.getPrototypeOf(document), Object.prototype)
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined)
  // `constructor` always resolves through the prototype, so assert on the
  // serialized members instead.
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(document)) as object).sort(), [
    'retryable',
    'status',
    'title',
    'type',
  ])
})

test('an unknown problem kind throws a coded error naming the kind', () => {
  assert.throws(
    () => buildProblem('does_not_exist' as ProblemKind),
    (error: Error & { code?: string }) => {
      assert.equal(error.code, 'FST_AGENT_POLICY_UNKNOWN_PROBLEM')
      assert.match(error.message, /does_not_exist/)
      return true
    },
  )
})

test('isValidProblemBaseUri accepts URIs and rejects everything else', () => {
  assert.equal(isValidProblemBaseUri('https://api.example/problems'), true)
  assert.equal(isValidProblemBaseUri('urn:example:problems'), true)
  assert.equal(isValidProblemBaseUri('/problems'), false)
  assert.equal(isValidProblemBaseUri('not a uri'), false)
  assert.equal(isValidProblemBaseUri(''), false)
  assert.equal(isValidProblemBaseUri(undefined), false)
  assert.equal(isValidProblemBaseUri(42), false)
})
