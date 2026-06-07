export interface User {
  id: string
  name: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  created_at: string
}

export interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
}
