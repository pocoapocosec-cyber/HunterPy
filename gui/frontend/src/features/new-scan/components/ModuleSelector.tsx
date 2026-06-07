import { useFormContext } from 'react-hook-form'
import type { ScanFormValues } from '../validation/scanSchema'
import { ALL_MODULES } from '@/lib/utils/constants'
import { cn } from '@/lib/cn'

export function ModuleSelector() {
  const { watch, setValue } = useFormContext<ScanFormValues>()
  const mode = watch('mode')
  const selected = watch('modules') || []

  if (mode !== 'custom') {
    return (
      <p className="text-xs text-text-muted">
        Modules are auto-selected by the <span className="text-text">{mode}</span> preset.
        Switch to <span className="text-text">custom</span> mode to choose manually.
      </p>
    )
  }

  function toggle(id: string) {
    const next = selected.includes(id)
      ? selected.filter((x) => x !== id)
      : [...selected, id]
    setValue('modules', next)
  }

  return (
    <div>
      <label className="block text-sm font-medium mb-2">Modules</label>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-1.5">
        {ALL_MODULES.map((m) => {
          const on = selected.includes(m.id)
          return (
            <button
              type="button"
              key={m.id}
              onClick={() => toggle(m.id)}
              className={cn(
                'rounded-md border px-2.5 py-1.5 text-xs text-left',
                on ? 'border-brand bg-brand/10 text-brand'
                   : 'border-line/40 text-text-muted hover:text-text'
              )}>
              <div className="font-medium">{m.label}</div>
              <div className="text-[10px] uppercase tracking-wide">{m.phase}</div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
