import { cn } from '@/lib/cn'
import { CopyButton } from './CopyButton'

export interface CodeBlockProps {
  code: string
  language?: string
  className?: string
}
export function CodeBlock({ code, language, className }: CodeBlockProps) {
  return (
    <div className={cn('relative group rounded-md bg-bg-deep border border-line/30',
                       className)}>
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100
                      transition-opacity">
        <CopyButton text={code} />
      </div>
      {language && (
        <div className="px-3 py-1.5 text-xs text-text-muted border-b border-line/30">
          {language}
        </div>
      )}
      <pre className="p-3 text-xs overflow-auto leading-relaxed
                       font-mono text-[#c5e3ff]"><code>{code}</code></pre>
    </div>
  )
}
