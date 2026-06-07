import { Pause, Play, Square, RefreshCw, Trash2 } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@components/ui/button'
import { scansAPI } from '@/lib/api/scans'
import { useToast } from '@components/ui/toast'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/config/routes'
import type { Scan } from '@app-types/scan'

export function ActionButtons({ scan }: { scan: Scan }) {
  const qc = useQueryClient()
  const toast = useToast()
  const nav = useNavigate()
  const reinvalidate = () => qc.invalidateQueries({ queryKey: ['scan', scan.id] })

  const pause  = useMutation({ mutationFn: () => scansAPI.pause(scan.id),
    onSuccess: () => { toast.push('Scan paused'); reinvalidate() } })
  const resume = useMutation({ mutationFn: () => scansAPI.resume(scan.id),
    onSuccess: () => { toast.push('Scan resumed'); reinvalidate() } })
  const cancel = useMutation({ mutationFn: () => scansAPI.cancel(scan.id),
    onSuccess: () => { toast.push('Scan cancelled'); reinvalidate() } })
  const remove = useMutation({ mutationFn: () => scansAPI.remove(scan.id),
    onSuccess: () => { toast.push('Scan deleted'); nav(ROUTES.scans) } })

  const isRunning = scan.status === 'running'
  const isPaused  = scan.status === 'paused'

  return (
    <div className="flex gap-2 flex-wrap">
      {isRunning && (
        <Button variant="outline" onClick={() => pause.mutate()} isLoading={pause.isPending}>
          <Pause className="h-4 w-4" /> Pause
        </Button>
      )}
      {isPaused && (
        <Button variant="outline" onClick={() => resume.mutate()} isLoading={resume.isPending}>
          <Play className="h-4 w-4" /> Resume
        </Button>
      )}
      {(isRunning || isPaused) && (
        <Button variant="outline" onClick={() => cancel.mutate()} isLoading={cancel.isPending}>
          <Square className="h-4 w-4" /> Cancel
        </Button>
      )}
      <Button variant="outline" onClick={reinvalidate}>
        <RefreshCw className="h-4 w-4" /> Refresh
      </Button>
      <Button variant="ghost" onClick={() => remove.mutate()}
              isLoading={remove.isPending}>
        <Trash2 className="h-4 w-4 text-severity-critical" />
      </Button>
    </div>
  )
}
