import { InputHTMLAttributes, forwardRef } from 'react'
import { cn } from '@/lib/cn'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...p }, ref) => (
    <input
      ref={ref}
      className={cn(
        'h-9 w-full rounded-md border border-line/40 bg-bg-deep px-3 text-sm',
        'placeholder:text-text-muted focus-visible:outline-none focus-visible:ring-2',
        'focus-visible:ring-brand/40 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
        'disabled:opacity-50',
        className
      )}
      {...p}
    />
  )
)
Input.displayName = 'Input'
