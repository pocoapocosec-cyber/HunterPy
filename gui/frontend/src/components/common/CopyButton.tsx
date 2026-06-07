import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@components/ui/button'

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      size="sm" variant="ghost"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch { /* ignore */ }
      }}
      aria-label="Copy"
    >
      {copied
        ? <Check className="h-3.5 w-3.5 text-severity-low" />
        : <Copy  className="h-3.5 w-3.5" />}
    </Button>
  )
}
