import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import type { Finding } from '@app-types/finding'
import { SEVERITY_COLORS } from '@/lib/utils/colors'

interface Node { id: string; r: number; color: string; label: string; count: number }

/** Simple radial "asset map" — groups findings by host. */
export function AttackSurfaceMap({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, { count: number; worst: number }>()
  const SEV_RANK: Record<string, number> = {
    critical: 5, high: 4, medium: 3, low: 2, info: 1,
  }
  for (const f of findings) {
    const host = (() => {
      try { return new URL(f.url).hostname } catch { return f.url || 'unknown' }
    })()
    const g = groups.get(host) || { count: 0, worst: 0 }
    g.count += 1
    g.worst = Math.max(g.worst, SEV_RANK[(f.severity || 'info').toLowerCase()] || 0)
    groups.set(host, g)
  }
  const nodes: Node[] = [...groups.entries()].map(([host, g]) => ({
    id: host, label: host, count: g.count,
    r: Math.min(40, 10 + g.count * 2),
    color: g.worst >= 5 ? SEVERITY_COLORS.critical
         : g.worst >= 4 ? SEVERITY_COLORS.high
         : g.worst >= 3 ? SEVERITY_COLORS.medium
         : g.worst >= 2 ? SEVERITY_COLORS.low
         : SEVERITY_COLORS.info,
  }))

  const w = 420, h = 240
  const cx = w / 2, cy = h / 2
  const n = nodes.length

  return (
    <Card>
      <CardHeader><CardTitle>Attack surface map</CardTitle></CardHeader>
      <CardContent>
        {n === 0 ? (
          <div className="text-sm text-text-muted py-8 text-center">
            No findings to plot.
          </div>
        ) : (
          <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-auto">
            <circle cx={cx} cy={cy} r={6} fill="#06b6d4" />
            {nodes.map((node, i) => {
              const angle = (i / n) * Math.PI * 2 - Math.PI / 2
              const dist = 90
              const x = cx + Math.cos(angle) * dist
              const y = cy + Math.sin(angle) * dist
              return (
                <g key={node.id}>
                  <line x1={cx} y1={cy} x2={x} y2={y}
                        stroke="#334155" strokeOpacity={0.5} />
                  <circle cx={x} cy={y} r={node.r / 2}
                          fill={node.color} fillOpacity={0.8}
                          stroke="#0f172a" strokeWidth={1.5}>
                    <title>{node.label}: {node.count} finding(s)</title>
                  </circle>
                  <text x={x} y={y + node.r / 2 + 12} textAnchor="middle"
                        className="fill-text" style={{ fontSize: 10 }}>
                    {node.label}
                  </text>
                </g>
              )
            })}
          </svg>
        )}
      </CardContent>
    </Card>
  )
}
