import { format, formatDistanceToNow, parseISO } from 'date-fns'

export function formatDate(iso?: string | null): string {
  if (!iso) return '—'
  try {
    return format(typeof iso === 'string' ? parseISO(iso) : iso, 'yyyy-MM-dd HH:mm')
  } catch {
    return String(iso)
  }
}

export function formatRelative(iso?: string | null): string {
  if (!iso) return '—'
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true })
  } catch {
    return String(iso)
  }
}

export function formatDuration(seconds: number): string {
  if (!seconds || seconds < 0) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  if (m < 60) return `${m}m ${s}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

export function formatNumber(n: number | undefined | null): string {
  if (n == null) return '—'
  return new Intl.NumberFormat().format(n)
}

export function truncate(s: string | undefined, len = 60): string {
  if (!s) return ''
  return s.length > len ? s.slice(0, len - 1) + '…' : s
}

export function formatBytes(bytes?: number): string {
  if (!bytes || bytes < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let n = bytes
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`
}
