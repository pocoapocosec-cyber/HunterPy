import type { ModuleStatus } from '@app-types/scan'
import { CheckCircle2, Loader2, XCircle, MinusCircle } from 'lucide-react'
import { cn } from '@/lib/cn'

const ICON = {
  pending:   <MinusCircle className="h-4 w-4 text-text-muted" />,
  running:   <Loader2 className="h-4 w-4 text-brand animate-spin" />,
  completed: <CheckCircle2 className="h-4 w-4 text-severity-low" />,
  failed:    <XCircle className="h-4 w-4 text-severity-critical" />,
  skipped:   <MinusCircle className="h-4 w-4 text-text-muted" />,
}

export function ModuleStatusList({ modules }: { modules: ModuleStatus[] }) {
  if (!modules?.length) return (
    <div className="text-sm text-text-muted py-4 text-center">No modules yet.</div>
  )
  return (
    <ul className="divide-y divide-line/20">
      {modules.map((m) => (
        <li key={m.name} className="flex items-center justify-between py-2 px-1">
          <div className="flex items-center gap-2">
            {ICON[m.status] || ICON.pending}
            <span className="text-sm font-medium">{m.name}</span>
            {m.error && (
              <span className="text-xs text-severity-critical">— {m.error}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-text-muted">
            <span>{m.findings_count} finding{m.findings_count === 1 ? '' : 's'}</span>
            <span className={cn(
              m.status === 'running' && 'text-brand',
              m.status === 'completed' && 'text-severity-low'
            )}>{m.status}</span>
          </div>
        </li>
      ))}
    </ul>
  )
}
