import { HTMLAttributes } from 'react'
import { cn } from '@/lib/cn'
import { AlertCircle, CheckCircle, Info, XCircle } from 'lucide-react'

type Tone = 'info' | 'success' | 'warning' | 'error'

const styles: Record<Tone, { box: string; icon: any }> = {
  info:    { box: 'bg-brand/10 border-brand/30 text-text',           icon: Info },
  success: { box: 'bg-severity-low/10 border-severity-low/40 text-text',   icon: CheckCircle },
  warning: { box: 'bg-severity-medium/10 border-severity-medium/40 text-text', icon: AlertCircle },
  error:   { box: 'bg-severity-critical/10 border-severity-critical/40 text-text', icon: XCircle },
}

export interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  tone?: Tone
  title?: string
}
export function Alert({ tone = 'info', title, children, className, ...p }: AlertProps) {
  const s = styles[tone]
  const Icon = s.icon
  return (
    <div className={cn('rounded-md border px-4 py-3 flex gap-3', s.box, className)} {...p}>
      <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
      <div className="text-sm">
        {title && <div className="font-medium mb-0.5">{title}</div>}
        {children}
      </div>
    </div>
  )
}
