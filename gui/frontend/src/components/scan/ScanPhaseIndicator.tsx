import { CheckCircle2, Circle, Loader2 } from 'lucide-react'
import { cn } from '@/lib/cn'
import type { ScanPhase } from '@app-types/scan'

const ORDER: { id: ScanPhase; label: string }[] = [
  { id: 'initialization',    label: 'Init' },
  { id: 'reconnaissance',    label: 'Recon' },
  { id: 'active_scanning',   label: 'Active' },
  { id: 'targeted_testing',  label: 'Targeted' },
  { id: 'auth_testing',      label: 'Auth' },
  { id: 'reporting',         label: 'Report' },
]

export function ScanPhaseIndicator({ current }: { current?: ScanPhase }) {
  const idx = ORDER.findIndex((p) => p.id === current)
  return (
    <ol className="flex items-center gap-3 text-xs">
      {ORDER.map((p, i) => {
        const state = idx === -1 ? 'pending'
          : i < idx ? 'done' : i === idx ? 'active' : 'pending'
        return (
          <li key={p.id} className="flex items-center gap-1.5">
            {state === 'done' && <CheckCircle2 className="h-3.5 w-3.5 text-severity-low" />}
            {state === 'active' && <Loader2 className="h-3.5 w-3.5 text-brand animate-spin" />}
            {state === 'pending' && <Circle className="h-3.5 w-3.5 text-text-muted" />}
            <span className={cn(
              state === 'active' && 'text-brand font-medium',
              state === 'pending' && 'text-text-muted'
            )}>{p.label}</span>
          </li>
        )
      })}
    </ol>
  )
}
