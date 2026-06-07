import { cn } from '@/lib/cn'

export interface ProgressProps {
  value: number  // 0..100
  className?: string
  variant?: 'default' | 'success' | 'warn' | 'danger'
}
const colorClass = {
  default: 'bg-brand',
  success: 'bg-severity-low',
  warn:    'bg-severity-medium',
  danger:  'bg-severity-critical',
}

export function Progress({ value, className, variant = 'default' }: ProgressProps) {
  const v = Math.max(0, Math.min(100, value))
  return (
    <div className={cn('w-full h-2 rounded-full bg-line/40 overflow-hidden', className)}
         role="progressbar" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100}>
      <div
        className={cn('h-full transition-all duration-300', colorClass[variant])}
        style={{ width: `${v}%` }}
      />
    </div>
  )
}
