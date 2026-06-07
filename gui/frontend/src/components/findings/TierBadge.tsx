import { cn } from '@/lib/cn'
import { tierClass } from '@/lib/utils/colors'
import type { Tier } from '@app-types/finding'

const EMOJI: Record<string, string> = {
  INTERESTING: '🔴', COMMON: '🟡', FALSE_ALARM: '🟢',
}

export function TierBadge({ tier }: { tier?: Tier | string }) {
  const t = (tier || 'COMMON').toUpperCase()
  return (
    <span className={cn(
      'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium',
      tierClass(t as Tier)
    )}>
      <span>{EMOJI[t] || '⚪'}</span>{t}
    </span>
  )
}
