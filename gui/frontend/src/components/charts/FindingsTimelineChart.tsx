import { useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { format, parseISO } from 'date-fns'
import type { Finding } from '@app-types/finding'

export function FindingsTimelineChart({ findings, days = 7, title = 'Findings over time' }:
  { findings: Finding[]; days?: number; title?: string }) {
  const series = useMemo(() => buildSeries(findings, days), [findings, days])
  const maxV = Math.max(1, ...series.map((p) => p.v))
  const w = 480, h = 160, padL = 28, padB = 22
  const innerW = w - padL - 8, innerH = h - padB - 8
  const stepX = innerW / Math.max(1, series.length - 1)

  return (
    <Card>
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent>
        <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-auto">
          {/* gridlines */}
          {[0, 0.5, 1].map((t) => (
            <line key={t}
                  x1={padL} x2={w - 8}
                  y1={8 + innerH * (1 - t)} y2={8 + innerH * (1 - t)}
                  stroke="#334155" strokeDasharray="3 3" />
          ))}
          {/* bars */}
          {series.map((p, i) => {
            const bh = (p.v / maxV) * innerH
            return (
              <rect key={i} x={padL + i * stepX - 6}
                    y={8 + innerH - bh} width={12} height={bh}
                    fill="#06b6d4" opacity={0.85}>
                <title>{p.label}: {p.v}</title>
              </rect>
            )
          })}
          {/* x labels */}
          {series.map((p, i) => (
            <text key={i} x={padL + i * stepX} y={h - 6}
                  textAnchor="middle" className="fill-text-muted"
                  style={{ fontSize: 10 }}>{p.label}</text>
          ))}
          {/* y max */}
          <text x={padL - 4} y={12} textAnchor="end"
                className="fill-text-muted" style={{ fontSize: 10 }}>{maxV}</text>
        </svg>
      </CardContent>
    </Card>
  )
}

function buildSeries(findings: Finding[], days: number) {
  const now = new Date()
  const buckets: { d: Date; v: number; label: string }[] = []
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now); d.setDate(now.getDate() - i)
    buckets.push({ d, v: 0, label: format(d, 'MM/dd') })
  }
  for (const f of findings) {
    const ts = f.discovered_at || f.created_at
    if (!ts) continue
    try {
      const dt = parseISO(ts)
      for (const b of buckets) {
        if (b.d.toDateString() === dt.toDateString()) { b.v += 1; break }
      }
    } catch { /* ignore */ }
  }
  return buckets
}
