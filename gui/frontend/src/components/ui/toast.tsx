import { createContext, ReactNode, useCallback, useContext, useState } from 'react'
import { cn } from '@/lib/cn'

type Tone = 'info' | 'success' | 'error'
interface Toast { id: number; tone: Tone; message: string }

interface Ctx {
  push: (message: string, tone?: Tone) => void
}
const ToastCtx = createContext<Ctx | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const push = useCallback((message: string, tone: Tone = 'info') => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, tone, message }])
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000)
  }, [])

  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
        {toasts.map((t) => (
          <div key={t.id}
            className={cn(
              'rounded-md border px-4 py-3 text-sm shadow-lg backdrop-blur',
              t.tone === 'success' && 'bg-severity-low/20 border-severity-low/40',
              t.tone === 'error'   && 'bg-severity-critical/20 border-severity-critical/40',
              t.tone === 'info'    && 'bg-bg-soft border-line/40'
            )}
          >{t.message}</div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export function useToast(): Ctx {
  const ctx = useContext(ToastCtx)
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>')
  return ctx
}
