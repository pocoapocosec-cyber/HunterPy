import type { Finding } from '@app-types/finding'

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export function downloadJSON(data: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  downloadBlob(blob, filename)
}

export function findingsToCSV(findings: Finding[]): string {
  const cols = ['id', 'severity', 'classification', 'module', 'title', 'url',
                'cvss', 'classification_confidence', 'discovered_at']
  const escape = (v: any) => {
    const s = String(v ?? '')
    return /["\n,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const rows = [cols.join(',')]
  for (const f of findings) {
    rows.push(cols.map((c) => escape((f as any)[c])).join(','))
  }
  return rows.join('\n')
}

export function downloadCSV(findings: Finding[], filename: string): void {
  downloadBlob(new Blob([findingsToCSV(findings)], { type: 'text/csv' }), filename)
}
