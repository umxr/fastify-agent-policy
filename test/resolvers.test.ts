import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyRequest } from 'fastify'

import agentPolicy, {
  bearerClaims,
  normalizeAgentOrigin,
  parseSignatureAgent,
  signatureAgent,
  userAgentPattern,
  webBotAuth,
  type WebBotAuthResult,
} from '../src/index.ts'

/** A stand-in request: the resolvers only read headers and decorations. */
function fakeRequest(request: Record<string, unknown>): FastifyRequest {
  return { headers: {}, ...request } as unknown as FastifyRequest
}

test('normalizeAgentOrigin keeps https origins and rejects everything else', () => {
  assert.equal(normalizeAgentOrigin('https://Agent.Example:443/keys'), 'https://agent.example')
  assert.equal(normalizeAgentOrigin('https://agent.example:8443/x'), 'https://agent.example:8443')
  assert.equal(normalizeAgentOrigin('http://agent.example'), null)
  assert.equal(normalizeAgentOrigin('data:text/plain,hi'), null)
  assert.equal(normalizeAgentOrigin('not a url'), null)
  assert.equal(normalizeAgentOrigin(undefined), null)
})

test('webBotAuth: no identity without verification', () => {
  const resolve = webBotAuth()

  assert.equal(resolve(fakeRequest({})), null)
  assert.equal(resolve(fakeRequest({ webBotAuth: null })), null)
  assert.equal(
    resolve(fakeRequest({ webBotAuth: { verified: false, agent: 'https://a.example' } })),
    null,
  )
  // `trusted` is undefined whenever `verified` is false. It is never read as
  // "falsy means denied".
  assert.equal(
    resolve(
      fakeRequest({
        webBotAuth: { verified: false, trusted: undefined, agent: 'https://a.example' },
      }),
    ),
    null,
  )
})

test('webBotAuth: verified maps to "verified", trusted maps to "trusted"', () => {
  const resolve = webBotAuth()

  const verified = resolve(
    fakeRequest({
      webBotAuth: { verified: true, agent: 'https://Agent.Example/', keyid: 'k1' },
    }),
  )
  assert.deepEqual(verified, {
    id: 'https://agent.example',
    class: 'verified',
    meta: { signatureAgent: 'https://Agent.Example/', keyid: 'k1' },
  })

  const trusted = resolve(
    fakeRequest({ webBotAuth: { verified: true, trusted: true, agent: 'https://a.example' } }),
  )
  assert.equal(trusted?.class, 'trusted')

  // A verified signature over a non-https agent is not an identity.
  assert.equal(
    resolve(fakeRequest({ webBotAuth: { verified: true, agent: 'http://a.example' } })),
    null,
  )
})

test('webBotAuth: the decoration property and scopes are configurable', () => {
  const resolve = webBotAuth({ property: 'botAuth', scopes: ['crawl:read'] })
  const result: WebBotAuthResult = { verified: true, trusted: true, agent: 'https://a.example' }
  assert.deepEqual(resolve(fakeRequest({ botAuth: result })), {
    id: 'https://a.example',
    class: 'trusted',
    // No `keyid: undefined` member: absent stays absent.
    meta: { signatureAgent: 'https://a.example' },
    scopes: ['crawl:read'],
  })
})

test('parseSignatureAgent handles the dictionary and the bare quoted forms', () => {
  assert.equal(parseSignatureAgent('sig="https://a.example"'), 'https://a.example')
  assert.equal(parseSignatureAgent('  sig="https://a.example"  '), 'https://a.example')
  assert.equal(parseSignatureAgent('"https://a.example"'), 'https://a.example')
  assert.equal(
    parseSignatureAgent('other="https://b.example", sig="https://a.example"'),
    'https://a.example',
  )
  // No `sig` member: fall back to the first one.
  assert.equal(parseSignatureAgent('binding="https://b.example"'), 'https://b.example')
  // A comma inside a quoted string is not a member separator.
  assert.equal(parseSignatureAgent('sig="https://a.example/x,y"'), 'https://a.example/x,y')
  // Parameters on the member value are ignored.
  assert.equal(parseSignatureAgent('sig="https://a.example";expires=99'), 'https://a.example')
  assert.equal(parseSignatureAgent(''), null)
  assert.equal(parseSignatureAgent('https://a.example'), null)
})

test('signatureAgent always yields an unverified identity', () => {
  const resolve = signatureAgent()

  assert.deepEqual(
    resolve(fakeRequest({ headers: { 'signature-agent': 'sig="https://Agent.Example/"' } })),
    {
      id: 'https://agent.example',
      class: 'unverified',
      meta: { signatureAgent: 'https://Agent.Example/' },
    },
  )
  assert.equal(
    resolve(fakeRequest({ headers: { 'signature-agent': '"https://a.example"' } }))?.class,
    'unverified',
  )
  assert.equal(resolve(fakeRequest({ headers: {} })), null)
  assert.equal(
    resolve(fakeRequest({ headers: { 'signature-agent': 'sig="http://a.example"' } })),
    null,
  )
})

test('signatureAgent works end to end through the plugin', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: signatureAgent(), applyTo: 'all' })
  app.get('/policed', { config: { agent: { risk: 'read' } } }, async (request) => ({
    agent: request.agent,
  }))
  await app.ready()

  const identified = await app.inject({
    method: 'GET',
    url: '/policed',
    headers: { 'signature-agent': 'sig="https://a.example"' },
  })
  assert.equal(identified.statusCode, 200)
  assert.equal(identified.json().agent.class, 'unverified')

  const anonymous = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(anonymous.statusCode, 401)

  await app.close()
})

test('bearerClaims maps verified claims and ignores their absence', () => {
  const resolve = bearerClaims<{ sub?: string; scope?: string }>((claims) =>
    typeof claims.sub === 'string'
      ? { id: claims.sub, scopes: claims.scope?.split(' '), class: 'verified' }
      : null,
  )

  assert.deepEqual(resolve(fakeRequest({ user: { sub: 'agent-7', scope: 'a b' } })), {
    id: 'agent-7',
    scopes: ['a', 'b'],
    class: 'verified',
  })
  assert.equal(resolve(fakeRequest({})), null)
  assert.equal(resolve(fakeRequest({ user: {} })), null)

  const custom = bearerClaims<{ sub: string }>((claims) => ({ id: claims.sub }), {
    claimsProperty: 'tokenClaims',
  })
  assert.deepEqual(custom(fakeRequest({ tokenClaims: { sub: 'x' } })), { id: 'x' })

  assert.throws(() => bearerClaims(undefined as never), TypeError)
})

test('userAgentPattern matches, captures and stays unverified', () => {
  const resolve = userAgentPattern([/^(MyAgent)\/[\d.]+$/, /GPTBot/])

  assert.deepEqual(resolve(fakeRequest({ headers: { 'user-agent': 'MyAgent/1.2' } })), {
    id: 'MyAgent',
    class: 'unverified',
    meta: { userAgent: 'MyAgent/1.2', pattern: '^(MyAgent)\\/[\\d.]+$' },
  })
  // No capture group: the whole match becomes the id.
  assert.equal(
    resolve(fakeRequest({ headers: { 'user-agent': 'Mozilla/5.0 (GPTBot/1.0)' } }))?.id,
    'GPTBot',
  )
  assert.equal(resolve(fakeRequest({ headers: { 'user-agent': 'curl/8' } })), null)
  assert.equal(resolve(fakeRequest({ headers: {} })), null)

  assert.throws(() => userAgentPattern([]), TypeError)
  assert.throws(() => userAgentPattern(['nope' as unknown as RegExp]), TypeError)
})

test('userAgentPattern is not confused by a global regex', () => {
  const resolve = userAgentPattern([/GPTBot/g])
  const request = fakeRequest({ headers: { 'user-agent': 'GPTBot/1.0' } })

  // A shared global regex carries `lastIndex`; the second call must still match.
  assert.equal(resolve(request)?.id, 'GPTBot')
  assert.equal(resolve(request)?.id, 'GPTBot')
})

test('resolver scopes are copied, never shared between identities', () => {
  const shared = ['crawl:read']

  const fromBotAuth = webBotAuth({ scopes: shared })
  const first = fromBotAuth(
    fakeRequest({ webBotAuth: { verified: true, agent: 'https://a.example' } }),
  )
  // A handler mutating `request.agent.scopes` must not reach the next request.
  first?.scopes?.push('orders:refund')
  const second = fromBotAuth(
    fakeRequest({ webBotAuth: { verified: true, agent: 'https://a.example' } }),
  )
  assert.deepEqual(second?.scopes, ['crawl:read'])
  assert.deepEqual(shared, ['crawl:read'])

  const fromUserAgent = userAgentPattern([/GPTBot/], { scopes: shared })
  const third = fromUserAgent(fakeRequest({ headers: { 'user-agent': 'GPTBot/1' } }))
  third?.scopes?.push('orders:refund')
  const fourth = fromUserAgent(fakeRequest({ headers: { 'user-agent': 'GPTBot/1' } }))
  assert.deepEqual(fourth?.scopes, ['crawl:read'])
  assert.deepEqual(shared, ['crawl:read'])
})

test('a semicolon inside a quoted value does not truncate it', () => {
  // Stripping parameters before unquoting turned this into an unterminated
  // string and dropped the identity entirely.
  assert.equal(parseSignatureAgent('sig="https://a.example/x;y"'), 'https://a.example/x;y')
  assert.equal(
    parseSignatureAgent('sig="https://a.example/x;y";expires=99'),
    'https://a.example/x;y',
  )
  assert.equal(parseSignatureAgent('"https://a.example/x;y"'), 'https://a.example/x;y')
  // Escaped quotes survive too.
  assert.equal(parseSignatureAgent('sig="https://a.example/\\"x"'), 'https://a.example/"x')
  // An unterminated string is still refused.
  assert.equal(parseSignatureAgent('sig="https://a.example'), null)
  // Trailing junk after a bare string is refused rather than silently kept.
  assert.equal(parseSignatureAgent('"https://a.example" trailing'), null)
})

test('a repeated Signature-Agent header cannot be overridden by a second value', () => {
  const resolve = signatureAgent()

  // Fastify hands back an array when the header arrives twice.
  const injected = resolve(
    fakeRequest({
      headers: { 'signature-agent': ['sig="https://real.example"', 'sig="https://evil.example"'] },
    }),
  )
  assert.equal(injected, null, 'disagreeing values yield no identity')

  // An exact duplicate is not ambiguous.
  const duplicated = resolve(
    fakeRequest({
      headers: { 'signature-agent': ['sig="https://real.example"', 'sig="https://real.example"'] },
    }),
  )
  assert.equal(duplicated?.id, 'https://real.example')

  // A single header is unaffected.
  assert.equal(
    resolve(fakeRequest({ headers: { 'signature-agent': ['sig="https://real.example"'] } }))?.id,
    'https://real.example',
  )

  // A garbage second value cannot displace a good first one either.
  assert.equal(
    resolve(
      fakeRequest({ headers: { 'signature-agent': ['sig="https://real.example"', 'garbage'] } }),
    )?.id,
    'https://real.example',
  )
})

test('a duplicate dictionary key does not displace the first value', () => {
  assert.equal(
    parseSignatureAgent('sig="https://real.example", sig="https://evil.example"'),
    'https://real.example',
  )
})
