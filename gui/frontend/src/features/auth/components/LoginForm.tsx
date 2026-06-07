import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Input } from '@components/ui/input'
import { Button } from '@components/ui/button'
import { Alert } from '@components/ui/alert'
import { useAuth } from '../hooks/useAuth'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/config/routes'

export function LoginForm() {
  const [user, setUser] = useState('')
  const [pw, setPw] = useState('')
  const { login } = useAuth()
  const nav = useNavigate()

  function submit(e: React.FormEvent) {
    e.preventDefault()
    // Mock: any non-empty credentials log you in
    if (!user || !pw) return
    login(`mock-token-${Date.now()}`)
    nav(ROUTES.dashboard)
  }

  return (
    <Card className="max-w-md w-full">
      <CardHeader><CardTitle>Sign in</CardTitle></CardHeader>
      <CardContent>
        <Alert tone="info">
          Mock mode: any non-empty username/password will work.
        </Alert>
        <form onSubmit={submit} className="space-y-3 mt-3">
          <Input placeholder="username" value={user}
                 onChange={(e) => setUser(e.target.value)} />
          <Input placeholder="password" type="password" value={pw}
                 onChange={(e) => setPw(e.target.value)} />
          <Button type="submit" variant="primary" className="w-full">
            Continue
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
