import { useEffect, useState } from 'react'
import { apiClient } from '@/lib/api/client'

export interface AuthState {
  token: string | null
  authenticated: boolean
}

export function useAuth(): AuthState & {
  login: (t: string) => void
  logout: () => void
} {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem('auth_token')
  )

  // In mock mode we don't enforce auth
  const authenticated = apiClient.useMocks || !!token

  useEffect(() => {
    if (token) localStorage.setItem('auth_token', token)
    else        localStorage.removeItem('auth_token')
  }, [token])

  return {
    token,
    authenticated,
    login: setToken,
    logout: () => setToken(null),
  }
}
