import type { Severity, Tier } from '@app-types/finding'

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#16a34a',
  info:     '#6b7280',
}

export const TIER_COLORS: Record<Tier, string> = {
  INTERESTING: '#dc2626',
  COMMON:      '#d97706',
  FALSE_ALARM: '#16a34a',
}

export function severityClass(s?: Severity | string): string {
  const k = (s || 'info').toLowerCase()
  return {
    critical: 'bg-severity-critical text-white',
    high:     'bg-severity-high text-white',
    medium:   'bg-severity-medium text-white',
    low:      'bg-severity-low text-white',
    info:     'bg-severity-info text-white',
  }[k] || 'bg-severity-info text-white'
}

export function tierClass(t?: Tier | string): string {
  const k = (t || 'COMMON').toUpperCase()
  return {
    INTERESTING: 'bg-tier-interesting text-white',
    COMMON:      'bg-tier-common text-white',
    FALSE_ALARM: 'bg-tier-falsealarm text-white',
  }[k] || 'bg-tier-common text-white'
}
