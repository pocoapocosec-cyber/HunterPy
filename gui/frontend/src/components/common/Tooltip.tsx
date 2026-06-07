import { ReactNode } from 'react'
import { cn } from '@/lib/cn'

export function Tooltip({ children, label, className }:
  { children: ReactNode; label: string; className?: string }) {
  return (
    <span className={cn('relative group inline-flex', className)}>
      {children}
      <span className="pointer-events-none absolute -top-8 left-1/2 -translate-x-1/2
                       whitespace-nowrap rounded bg-bg-deep px-2 py-1 text-xs
                       text-text border border-line/40 opacity-0
                       group-hover:opacity-100 transition-opacity z-20">
        {label}
      </span>
    </span>
  )
}
