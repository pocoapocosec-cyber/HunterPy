import { Input } from '@components/ui/input'
import { useFormContext } from 'react-hook-form'
import type { ScanFormValues } from '../validation/scanSchema'
import { useDebounce } from '@/lib/hooks/useDebounce'
import { useEffect, useState } from 'react'
import { scansAPI } from '@/lib/api/scans'

export function TargetInput() {
  const { register, watch, formState: { errors } } = useFormContext<ScanFormValues>()
  const value = watch('target') || ''
  const debounced = useDebounce(value, 400)
  const [validation, setValidation] = useState<{ valid: boolean; reason?: string } | null>(null)

  useEffect(() => {
    let active = true
    if (!debounced) { setValidation(null); return }
    scansAPI.validateTarget(debounced)
      .then((r) => { if (active) setValidation(r) })
      .catch(() => { if (active) setValidation(null) })
    return () => { active = false }
  }, [debounced])

  return (
    <div>
      <label className="block text-sm font-medium mb-1">Target URL or hostname</label>
      <Input placeholder="https://example.com" {...register('target')} />
      {errors.target && (
        <p className="text-xs text-severity-critical mt-1">{errors.target.message}</p>
      )}
      {validation && !errors.target && (
        <p className={`text-xs mt-1 ${validation.valid ? 'text-severity-low' : 'text-severity-critical'}`}>
          {validation.valid ? '✓ Target accepted' : `✗ ${validation.reason}`}
        </p>
      )}
    </div>
  )
}
