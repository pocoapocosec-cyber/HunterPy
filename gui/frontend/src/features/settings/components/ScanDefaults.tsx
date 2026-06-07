import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Input } from '@components/ui/input'
import { Select } from '@components/ui/select'
import { useSettings } from '../hooks/useSettings'
import { SCAN_MODES } from '@/lib/utils/constants'

export function ScanDefaults() {
  const [s, set] = useSettings()
  return (
    <Card>
      <CardHeader><CardTitle>Scan defaults</CardTitle></CardHeader>
      <CardContent className="grid grid-cols-2 gap-3">
        <Field label="Default mode">
          <Select value={s.defaultMode}
                  onChange={(e) => set({ ...s, defaultMode: e.target.value })}>
            {SCAN_MODES.map((m) => <option key={m.value} value={m.value}>{m.value}</option>)}
          </Select>
        </Field>
        <Field label="Default threads">
          <Input type="number" value={s.defaultThreads}
                 onChange={(e) => set({ ...s, defaultThreads: Number(e.target.value) })} />
        </Field>
        <Field label="Default rate (req/s)">
          <Input type="number" value={s.defaultRateLimit}
                 onChange={(e) => set({ ...s, defaultRateLimit: Number(e.target.value) })} />
        </Field>
      </CardContent>
    </Card>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-xs text-text-muted mb-1">{label}</label>
      {children}
    </div>
  )
}
