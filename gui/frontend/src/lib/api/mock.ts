/**
 * Static mock adapter. When VITE_USE_MOCKS=true the API modules read from
 * `public/mock/*.json` instead of hitting a backend. This lets the whole
 * frontend run end-to-end with no server.
 */
import type { Scan, ScanProgress, ModuleStatus } from '@app-types/scan'
import type { Finding } from '@app-types/finding'
import type { TargetInfo } from '@app-types/target'
import type { Report } from '@app-types/report'

async function loadJSON<T>(path: string): Promise<T> {
  const r = await fetch(path)
  if (!r.ok) throw new Error(`mock load failed: ${path} (${r.status})`)
  return r.json()
}

let _scans: Scan[] | null = null
let _findings: Finding[] | null = null
let _modules: ModuleStatus[] | null = null
let _target: TargetInfo | null = null
let _report: Report | null = null

export const mock = {
  async scans(): Promise<Scan[]> {
    if (!_scans) _scans = await loadJSON<Scan[]>('/mock/scans.json')
    return _scans!
  },
  async findings(): Promise<Finding[]> {
    if (!_findings) _findings = await loadJSON<Finding[]>('/mock/findings.json')
    return _findings!
  },
  async modules(): Promise<ModuleStatus[]> {
    if (!_modules) _modules = await loadJSON<ModuleStatus[]>('/mock/modules.json')
    return _modules!
  },
  async target(): Promise<TargetInfo> {
    if (!_target) _target = await loadJSON<TargetInfo>('/mock/target.json')
    return _target!
  },
  async report(): Promise<Report> {
    if (!_report) _report = await loadJSON<Report>('/mock/report.json')
    return _report!
  },

  async progress(scanId: string): Promise<ScanProgress> {
    return {
      scan_id: scanId,
      phase: 'reconnaissance',
      phase_name: 'Reconnaissance',
      percent: 42,
      current_module: 'tech_fingerprint',
      modules_completed: 3,
      modules_total: 9,
      elapsed_time: 28,
      estimated_remaining: 42,
      status: 'running',
    }
  },

  reset() {
    _scans = _findings = _modules = null
    _target = null
    _report = null
  },
}
