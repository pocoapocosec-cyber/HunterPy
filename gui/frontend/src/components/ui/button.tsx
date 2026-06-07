import { ButtonHTMLAttributes, forwardRef } from 'react'
import { cn } from '@/lib/cn'

type Variant = 'default' | 'primary' | 'destructive' | 'ghost' | 'outline'
type Size = 'sm' | 'md' | 'lg' | 'icon'

const variantClass: Record<Variant, string> = {
  default:     'bg-bg-soft hover:bg-line/40 text-text border border-line/40',
  primary:     'bg-brand text-white hover:bg-brand/90',
  destructive: 'bg-severity-critical text-white hover:bg-severity-critical/90',
  ghost:       'hover:bg-line/30 text-text',
  outline:     'border border-line/40 text-text hover:bg-line/30',
}
const sizeClass: Record<Size, string> = {
  sm:   'h-8 px-3 text-sm',
  md:   'h-9 px-4 text-sm',
  lg:   'h-11 px-6 text-base',
  icon: 'h-9 w-9 p-0 grid place-items-center',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  isLoading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'md', isLoading, disabled,
     children, ...rest }, ref) => (
    <button
      ref={ref}
      disabled={disabled || isLoading}
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-md font-medium',
        'transition-colors focus-visible:outline-none focus-visible:ring-2',
        'focus-visible:ring-brand/40 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
        'disabled:opacity-50 disabled:pointer-events-none',
        variantClass[variant], sizeClass[size], className
      )}
      {...rest}
    >
      {isLoading && (
        <span className="inline-block h-3 w-3 rounded-full border-2 border-current
          border-r-transparent animate-spin" />
      )}
      {children}
    </button>
  )
)
Button.displayName = 'Button'
