import type { FastifyRequest } from 'fastify'

import type { AgentIdentity, SyncAgentIdentityResolver } from '../types.js'
import { normalizeAgentOrigin } from './web-bot-auth.js'

/** Options for {@link signatureAgent}. */
export interface SignatureAgentResolverOptions {
  /** Header to read. Defaults to `signature-agent`. */
  header?: string
  /** Dictionary key to prefer. Defaults to `sig`. */
  key?: string
}

/**
 * Splits an RFC 8941 dictionary on top-level commas, ignoring commas that sit
 * inside a quoted string.
 */
function splitMembers(value: string): string[] {
  const members: string[] = []
  let current = ''
  let inQuotes = false
  let escaped = false

  for (const char of value) {
    if (escaped) {
      current += char
      escaped = false
      continue
    }
    if (char === '\\' && inQuotes) {
      current += char
      escaped = true
      continue
    }
    if (char === '"') {
      inQuotes = !inQuotes
      current += char
      continue
    }
    if (char === ',' && !inQuotes) {
      members.push(current)
      current = ''
      continue
    }
    current += char
  }
  members.push(current)
  return members
}

/**
 * Reads an RFC 8941 String (`"..."`) from the start of `value`.
 *
 * Stops at the closing quote and reports where it stopped, so a caller can
 * drop trailing parameters without cutting into the string. Splitting on `;`
 * first would truncate `"https://a.example/x;y"` to an unterminated string
 * and silently drop the identity.
 */
function readQuotedString(value: string): { value: string; end: number } | null {
  const trimmed = value.trimStart()
  const offset = value.length - trimmed.length
  if (!trimmed.startsWith('"')) return null

  let out = ''
  for (let index = 1; index < trimmed.length; index += 1) {
    const char = trimmed[index]
    if (char === '\\') {
      const next = trimmed[index + 1]
      if (next === undefined) return null
      out += next
      index += 1
      continue
    }
    if (char === '"') return { value: out, end: offset + index + 1 }
    out += char
  }
  // Ran off the end without a closing quote.
  return null
}

/** Unwraps a complete RFC 8941 String, rejecting trailing junk. */
function parseQuotedString(value: string): string | null {
  const read = readQuotedString(value)
  if (read === null) return null
  if (value.slice(read.end).trim().length > 0) return null
  return read.value
}

/**
 * Parses a `Signature-Agent` header value.
 *
 * Accepts both forms seen in the wild:
 * - the RFC 8941 Dictionary form, `sig="https://agent.example"`
 * - the legacy bare quoted-string form, `"https://agent.example"`
 *
 * Returns the raw string value, or `null` when the header does not parse.
 */
export function parseSignatureAgent(value: string, key = 'sig'): string | null {
  const trimmed = value.trim()
  if (trimmed.length === 0) return null

  // Legacy bare quoted-string form.
  if (trimmed.startsWith('"')) {
    return parseQuotedString(trimmed)
  }

  // Dictionary form. Prefer the named key, fall back to the first member.
  // The first occurrence of a key wins: a duplicate appended by an attacker
  // must never displace the value the client actually sent.
  let fallback: string | null = null
  for (const member of splitMembers(trimmed)) {
    const separator = member.indexOf('=')
    if (separator === -1) continue
    const memberKey = member.slice(0, separator).trim()

    const rawValue = member.slice(separator + 1)
    const read = readQuotedString(rawValue)
    if (read === null) continue
    // Anything after the closing quote is a parameter (`;expires=...`), so it
    // is dropped -- but only once the string itself has been read.
    const rest = rawValue.slice(read.end).trim()
    if (rest.length > 0 && !rest.startsWith(';')) continue

    if (memberKey === key) return read.value
    if (fallback === null) fallback = read.value
  }
  return fallback
}

/**
 * Reads the `Signature-Agent` header.
 *
 * The value is never verified, so the identity is always
 * `class: 'unverified'`. The Web Bot Auth draft forbids attaching policy to
 * an unverified signature agent -- treat this resolver as telemetry, or pair
 * it with {@link webBotAuth} behind your own trust decision.
 */
export function signatureAgent(
  options: SignatureAgentResolverOptions = {},
): SyncAgentIdentityResolver {
  const header = (options.header ?? 'signature-agent').toLowerCase()
  const key = options.key ?? 'sig'

  return function resolveSignatureAgent(request: FastifyRequest): AgentIdentity | null {
    const raw = request.headers[header]
    if (raw === undefined) return null

    // Fastify hands back an array when the header arrives more than once.
    // Each value is parsed on its own and the results must agree: a second
    // header must not override the first, and it must not be quietly
    // ignored either. Disagreement means no identity.
    const values = Array.isArray(raw) ? raw : [raw]
    const parsed = new Set<string>()
    for (const value of values) {
      const agent = parseSignatureAgent(value, key)
      if (agent !== null) parsed.add(agent)
    }
    if (parsed.size !== 1) return null

    const [agent] = [...parsed]
    if (agent === undefined) return null

    const id = normalizeAgentOrigin(agent)
    if (id === null) return null

    return {
      id,
      class: 'unverified',
      meta: { signatureAgent: agent },
    }
  }
}
