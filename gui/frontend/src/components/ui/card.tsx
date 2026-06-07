import { HTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export function Card({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card', className)} {...p} />
}
export function CardHeader({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-4 border-b border-line/30', className)} {...p} />
}
export function CardTitle({ className, ...p }: HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn('text-base font-semibold', className)} {...p} />
}
export function CardDescription({ className, ...p }: HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-sm text-text-muted', className)} {...p} />
}
export function CardContent({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-5', className)} {...p} />
}
export function CardFooter({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-3 border-t border-line/30', className)} {...p} />
}
