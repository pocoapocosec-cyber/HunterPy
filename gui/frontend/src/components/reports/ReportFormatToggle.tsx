import type { ReportFormat } from '@app-types/report'
import { cn } from '@/lib/cn'

const ALL: ReportFormat[] = ['html', 'json', 'markdown', 'csv']

export function ReportFormatToggle({ value, onChange }:
  { value: ReportFormat; onChange: (f: ReportFormat) => void }) {
  return (
    <div className="inline-flex rounded-md border border-line/40 overflow-hidden">
      {ALL.map((f) => (
        <button key={f}
                onClick={() => onChange(f)}
                className={cn('px-3 py-1.5 text-xs uppercase tracking-wide',
                  value === f ? 'bg-brand text-white'
                              : 'text-text-muted hover:bg-line/30')}
        >{f}</button>
      ))}
    </div>
  )
}
