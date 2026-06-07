import { Zap } from 'lucide-react'
import { Button } from '@components/ui/button'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/config/routes'

export function QuickScanButton() {
  const nav = useNavigate()
  return (
    <Button variant="primary" onClick={() => nav(ROUTES.newScan + '?mode=quick')}>
      <Zap className="h-4 w-4" /> Quick scan
    </Button>
  )
}
