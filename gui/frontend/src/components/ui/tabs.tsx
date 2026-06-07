import { ReactNode, useState } from 'react'
import { cn } from '@/lib/cn'

export interface TabItem { id: string; label: ReactNode; content: ReactNode }

export interface TabsProps {
  items: TabItem[]
  defaultId?: string
  className?: string
}
export function Tabs({ items, defaultId, className }: TabsProps) {
  const [active, setActive] = useState(defaultId || items[0]?.id)
  const current = items.find((i) => i.id === active) || items[0]
  return (
    <div className={cn('w-full', className)}>
      <div role="tablist" className="flex gap-1 border-b border-line/30">
        {items.map((it) => (
          <button
            key={it.id}
            role="tab"
            aria-selected={active === it.id}
            onClick={() => setActive(it.id)}
            className={cn(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              active === it.id
                ? 'border-brand text-brand'
                : 'border-transparent text-text-muted hover:text-text'
            )}
          >{it.label}</button>
        ))}
      </div>
      <div className="pt-4">{current?.content}</div>
    </div>
  )
}
