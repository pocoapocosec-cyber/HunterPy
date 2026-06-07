import { useFormContext } from 'react-hook-form'
import type { ScanFormValues } from '../validation/scanSchema'
import { SCAN_MODES } from '@/lib/utils/constants'
import { cn } from '@/lib/cn'

export function ModeSelector() {
  const { watch, setValue } = useFormContext<ScanFormValues>()
  const current = watch('mode')
  return (
    <div>
      <label className="block text-sm font-medium mb-2">Scan mode</label>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
        {SCAN_MODES.map((m) => (
          <button
            type="button"
            key={m.value}
            onClick={() => setValue('mode', m.value, { shouldValidate: true })}
            className={cn(
              'rounded-md border px-3 py-2 text-sm text-left transition-colors',
              current === m.value
                ? 'border-brand bg-brand/10 text-brand'
                : 'border-line/40 hover:border-line text-text-muted hover:text-text'
            )}
          >
            <div className="font-medium capitalize">{m.value}</div>
            <div className="text-xs text-text-muted mt-0.5">{m.label}</div>
          </button>
        ))}
      </div>
    </div>
  )
}
