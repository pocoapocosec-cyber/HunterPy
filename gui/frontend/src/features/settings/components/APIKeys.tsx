import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Input } from '@components/ui/input'
import { useSettings } from '../hooks/useSettings'

export function APIKeys() {
  const [s, set] = useSettings()
  return (
    <Card>
      <CardHeader><CardTitle>API keys</CardTitle></CardHeader>
      <CardContent className="space-y-2">
        <label className="block text-xs text-text-muted">NVD API key</label>
        <Input type="password" value={s.nvdApiKey}
               placeholder="(optional — set $NVD_API_KEY on the backend instead)"
               onChange={(e) => set({ ...s, nvdApiKey: e.target.value })} />
        <p className="text-xs text-text-muted">
          Stored only in your browser's localStorage. Never sent to a third party.
        </p>
      </CardContent>
    </Card>
  )
}
