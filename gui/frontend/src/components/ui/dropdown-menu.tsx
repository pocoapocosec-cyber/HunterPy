import { ReactNode, useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'

export interface DropdownMenuProps {
  trigger: ReactNode
  children: ReactNode
  align?: 'left' | 'right'
}
export function DropdownMenu({ trigger, children, align = 'right' }: DropdownMenuProps) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    if (open) document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  return (
    <div className="relative inline-block" ref={ref}>
      <div onClick={() => setOpen((v) => !v)}>{trigger}</div>
      {open && (
        <div
          role="menu"
          className={cn(
            'absolute z-20 mt-1 min-w-[180px] rounded-md border border-line/40',
            'bg-bg-soft shadow-lg py-1',
            align === 'right' ? 'right-0' : 'left-0'
          )}
          onClick={() => setOpen(false)}
        >
          {children}
        </div>
      )}
    </div>
  )
}
export function DropdownItem({ children, onClick, danger = false }:
  { children: ReactNode; onClick?: () => void; danger?: boolean }) {
  return (
    <button
      role="menuitem"
      onClick={onClick}
      className={cn(
        'w-full text-left px-3 py-1.5 text-sm hover:bg-line/30',
        danger && 'text-severity-critical hover:bg-severity-critical/10'
      )}
    >{children}</button>
  )
}
