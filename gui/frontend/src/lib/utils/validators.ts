const DOMAIN_RE =
  /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/

export function isValidTarget(input: string): boolean {
  if (!input) return false
  const cleaned = input.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '')
  return DOMAIN_RE.test(cleaned) || IPV4_RE.test(cleaned)
}

export function isValidUrl(input: string): boolean {
  try {
    const u = new URL(input)
    return u.protocol === 'http:' || u.protocol === 'https:'
  } catch {
    return false
  }
}

export const FORBIDDEN_HOSTS = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', '::1',
])

export function isForbiddenTarget(input: string): boolean {
  const cleaned = input.trim().toLowerCase().replace(/^https?:\/\//i, '').split('/')[0]
  if (FORBIDDEN_HOSTS.has(cleaned)) return true
  if (cleaned.endsWith('.gov') || cleaned.endsWith('.mil')) return true
  return false
}
