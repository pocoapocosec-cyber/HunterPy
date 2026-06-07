import { useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { SEVERITY_COLORS } from '@/lib/utils/colors'
import type { Severity } from '@app-types/finding'

export interface SeverityPieChartProps {
  /** keys are severity strings, values are counts */
  data: Partial<Record<Severity | string, number>>
  size?: number
  title?: string
}

export function SeverityPieChart({ data, size = 180, title = 'Findings by severity' }:
  SeverityPieChartProps) {
  const slices = useMemo(() => {
    const entries = Object.entries(data || {})
      .filter(([, v]) => (v ?? 0) > 0)
      .map(([k, v]) => ({
        key: k.toLowerCase(),
        value: v as number,
        color: SEVERITY_COLORS[k.toLowerCase() as Severity] || '#6b7280',
      }))
    const total = entries.reduce((s, e) => s + e.value, 0) || 1
    let cum = 0
    return entries.map((e) => {
      const start = cum / total
      cum += e.value
      const end = cum / total
      return { ...e, start, end, pct: e.value / total }
    })
  }, [data])

  const cx = size / 2, cy = size / 2, r = size / 2 - 6
  const total = slices.reduce((s, e) => s + e.value, 0)

  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent>
        <div className="flex items-center gap-6">
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
            {total === 0 ? (
              <circle cx={cx} cy={cy} r={r} fill="none" stroke="#334155" strokeWidth={2} />
            ) : slices.map((s, i) => (
              <path key={i} d={arcPath(cx, cy, r, s.start, s.end)}
                    fill={s.color} stroke="#0f172a" strokeWidth={1.5} />
            ))}
            <text x={cx} y={cy} textAnchor="middle" dominantBaseline="central"
                  className="fill-text font-semibold" style={{ fontSize: 18 }}>
              {total}
            </text>
          </svg>
          <ul className="text-sm space-y-1">
            {slices.length === 0 && (
              <li className="text-text-muted">No findings to chart.</li>
            )}
            {slices.map((s) => (
              <li key={s.key} className="flex items-center gap-2">
                <span className="inline-block w-3 h-3 rounded-sm"
                      style={{ background: s.color }} />
                <span className="capitalize w-20">{s.key}</span>
                <span className="font-mono text-text-muted">
                  {s.value} ({(s.pct * 100).toFixed(0)}%)
                </span>
              </li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

function arcPath(cx: number, cy: number, r: number, start: number, end: number) {
  if (end - start >= 0.9999) {
    return `M ${cx - r} ${cy} a ${r} ${r} 0 1 0 ${r * 2} 0
            a ${r} ${r} 0 1 0 ${-r * 2} 0`
  }
  const a0 = start * Math.PI * 2 - Math.PI / 2
  const a1 = end   * Math.PI * 2 - Math.PI / 2
  const x0 = cx + r * Math.cos(a0)
  const y0 = cy + r * Math.sin(a0)
  const x1 = cx + r * Math.cos(a1)
  const y1 = cy + r * Math.sin(a1)
  const large = end - start > 0.5 ? 1 : 0
  return `M ${cx} ${cy} L ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1} Z`
}
