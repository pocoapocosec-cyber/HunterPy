import { SelectHTMLAttributes, forwardRef } from 'react'
import { cn } from '@/lib/cn'

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...p }, ref) => (
    <select
      ref={ref}
      className={cn(
        'h-9 w-full rounded-md border border-line/40 bg-bg-deep px-3 text-sm',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40',
        className
      )}
      {...p}
    >
      {children}
    </select>
  )
)
Select.displayName = 'Select'
