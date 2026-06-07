import { Link } from 'react-router-dom'
import { Plus, Activity } from 'lucide-react'
import { Button } from '@components/ui/button'
import { ROUTES } from '@/config/routes'

export function QuickActions() {
  return (
    <div className="flex gap-2">
      <Link to={ROUTES.newScan}>
        <Button variant="primary"><Plus className="h-4 w-4" /> New scan</Button>
      </Link>
      <Link to={ROUTES.scans}>
        <Button variant="outline"><Activity className="h-4 w-4" /> All scans</Button>
      </Link>
    </div>
  )
}
