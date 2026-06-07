import { HTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'outline' | 'success' | 'warn' | 'danger'
}
const variantClass = {
  default: 'bg-line/30 text-text',
  outline: 'border border-line/50 text-text',
  success: 'bg-severity-low/20 text-severity-low',
  warn:    'bg-severity-medium/20 text-severity-medium',
  danger:  'bg-severity-critical/20 text-severity-critical',
}
export function Badge({ className, variant = 'default', ...p }: BadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
      variantClass[variant], className
    )} {...p} />
  )
}
