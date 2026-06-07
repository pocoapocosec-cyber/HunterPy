import { ReactNode } from 'react'
import { Inbox } from 'lucide-react'
import { cn } from '@/lib/cn'

export interface EmptyStateProps {
  title: string
  description?: string
  icon?: ReactNode
  action?: ReactNode
  className?: string
}
export function EmptyState({ title, description, icon, action, className }: EmptyStateProps) {
  return (
    <div className={cn(
      'flex flex-col items-center justify-center text-center py-12 px-4',
      className
    )}>
      <div className="text-text-muted mb-3">
        {icon || <Inbox className="h-10 w-10" />}
      </div>
      <h3 className="font-semibold text-base mb-1">{title}</h3>
      {description && (
        <p className="text-sm text-text-muted max-w-md mb-4">{description}</p>
      )}
      {action}
    </div>
  )
}
