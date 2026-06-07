import type { Finding } from '@app-types/finding'
import { Card, CardContent } from '@components/ui/card'

export function FindingStats({ findings }: { findings: Finding[] }) {
  const counts = findings.reduce((acc, f) => {
    const t = (f.classification || f.tier || 'COMMON').toUpperCase()
    acc[t] = (acc[t] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const items = [
    { label: '🔴 Interesting', value: counts.INTERESTING || 0, color: 'text-tier-interesting' },
    { label: '🟡 Common',      value: counts.COMMON      || 0, color: 'text-tier-common' },
    { label: '🟢 False alarm', value: counts.FALSE_ALARM || 0, color: 'text-tier-falsealarm' },
  ]
  return (
    <div className="grid grid-cols-3 gap-3">
      {items.map((it) => (
        <Card key={it.label}>
          <CardContent>
            <div className="text-xs text-text-muted">{it.label}</div>
            <div className={`text-2xl font-bold ${it.color}`}>{it.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
