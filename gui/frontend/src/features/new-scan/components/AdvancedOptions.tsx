import { useFormContext } from 'react-hook-form'
import type { ScanFormValues } from '../validation/scanSchema'
import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Input } from '@components/ui/input'

export function AdvancedOptions() {
  const [open, setOpen] = useState(false)
  const { register } = useFormContext<ScanFormValues>()

  return (
    <div>
      <button type="button"
              onClick={() => setOpen((o) => !o)}
              className="text-sm flex items-center gap-1 text-text-muted hover:text-text">
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        Advanced options
      </button>
      {open && (
        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Threads"   type="number" {...register('threads')} />
          <Field label="Rate limit (req/s)" type="number" {...register('rate_limit')} />
          <Field label="Timeout (s)" type="number" {...register('timeout')} />
          <Field label="Delay (s)"  type="number" step="0.1" {...register('delay')} />
          <Field label="Proxy URL"  placeholder="http://127.0.0.1:8080" {...register('proxy')} />
          <Field label="User-Agent" {...register('user_agent')} />
          <Field label="Cookies"    placeholder="key=value; key2=value2" {...register('cookies')} />
          <Field label="Auth URL"   placeholder="https://target/login" {...register('auth_url')} />
          <Field label="Username list" {...register('username_list')} />
          <Field label="Password list" {...register('password_list')} />
        </div>
      )}
    </div>
  )
}

function Field(props: any) {
  const { label, ...rest } = props
  return (
    <div>
      <label className="block text-xs text-text-muted mb-1">{label}</label>
      <Input {...rest} />
    </div>
  )
}
