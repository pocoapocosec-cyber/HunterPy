import { Link } from 'react-router-dom'
import { Button } from '@components/ui/button'
import { ROUTES } from '@/config/routes'

export function NotFound() {
  return (
    <div className="min-h-[60vh] grid place-items-center text-center">
      <div className="space-y-3">
        <div className="text-6xl font-extrabold text-brand">404</div>
        <p className="text-text-muted">That page doesn't exist.</p>
        <Link to={ROUTES.dashboard}>
          <Button variant="primary">Back to dashboard</Button>
        </Link>
      </div>
    </div>
  )
}
