import { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { ROUTES } from '@/config/routes'

export function AuthGuard({ children }: { children: ReactNode }) {
  const { authenticated } = useAuth()
  const loc = useLocation()
  if (!authenticated) {
    return <Navigate to={ROUTES.login} state={{ from: loc }} replace />
  }
  return <>{children}</>
}
