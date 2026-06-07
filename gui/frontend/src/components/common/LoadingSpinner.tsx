import { cn } from '@/lib/cn'
import { Loader2 } from 'lucide-react'

export function LoadingSpinner({ className, label = 'Loading…' }:
  { className?: string; label?: string }) {
  return (
    <div className={cn('flex items-center gap-2 text-text-muted', className)}>
      <Loader2 className="h-4 w-4 animate-spin" />
      <span className="text-sm">{label}</span>
    </div>
  )
}
