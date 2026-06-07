import { HTMLAttributes, TdHTMLAttributes, ThHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export function Table({ className, ...p }: HTMLAttributes<HTMLTableElement>) {
  return <table className={cn('w-full text-sm', className)} {...p} />
}
export function TableHeader({ className, ...p }: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn('[&_tr]:border-b [&_tr]:border-line/30', className)} {...p} />
}
export function TableBody({ className, ...p }: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn('[&_tr]:border-b [&_tr]:border-line/20', className)} {...p} />
}
export function TableRow({ className, ...p }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn('hover:bg-line/15 transition-colors', className)} {...p} />
}
export function TableHead({ className, ...p }: ThHTMLAttributes<HTMLTableCellElement>) {
  return <th className={cn(
    'px-3 py-2 text-left font-medium text-text-muted',
    className)} {...p} />
}
export function TableCell({ className, ...p }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn('px-3 py-2 align-top', className)} {...p} />
}
