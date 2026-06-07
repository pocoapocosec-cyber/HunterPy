import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { useSettings } from '../hooks/useSettings'

export function GeneralSettings() {
  const [s, set] = useSettings()
  return (
    <Card>
      <CardHeader><CardTitle>General</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="accent-brand"
                 checked={s.notificationsEnabled}
                 onChange={(e) => set({ ...s, notificationsEnabled: e.target.checked })} />
          Enable in-app notifications
        </label>
      </CardContent>
    </Card>
  )
}
