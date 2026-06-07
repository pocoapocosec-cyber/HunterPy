import { cn } from '@/lib/cn'
import { severityClass } from '@/lib/utils/colors'
import type { Severity } from '@app-types/finding'

export function SeverityBadge({ severity }: { severity?: Severity | string }) {
  const s = (severity || 'info').toUpperCase()
  return (
    <span className={cn(
      'inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold',
      severityClass((severity || 'info') as Severity)
    )}>{s}</span>
  )
}
