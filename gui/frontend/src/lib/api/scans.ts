import { apiClient } from './client'
import { ENDPOINTS } from './endpoints'
import { mock } from './mock'
import type {
  Scan, ScanOptions, ScanProgress, ScanStatus, ModuleStatus,
} from '@app-types/scan'
import type { TargetInfo } from '@app-types/target'

export interface ScanListParams {
  status?: ScanStatus
  limit?: number
  offset?: number
}

export const scansAPI = {
  async list(params?: ScanListParams) {
    if (apiClient.useMocks) {
      const all = await mock.scans()
      const filtered = params?.status
        ? all.filter((s) => s.status === params.status)
        : all
      return { scans: filtered, total: filtered.length }
    }
    return apiClient.get<{ scans: Scan[]; total: number }>(ENDPOINTS.scans, { params })
  },

  async get(scanId: string): Promise<Scan> {
    if (apiClient.useMocks) {
      const all = await mock.scans()
      const found = all.find((s) => s.id === scanId)
      if (!found) throw new Error(`scan ${scanId} not found`)
      return found
    }
    return apiClient.get<Scan>(ENDPOINTS.scan(scanId))
  },

  async create(data: {
    target: string
    mode: string
    modules?: string[]
    options?: Partial<ScanOptions>
  }): Promise<Scan> {
    if (apiClient.useMocks) {
      const id = `scan_${Date.now()}`
      const scan: Scan = {
        id,
        target: data.target,
        mode: data.mode as any,
        status: 'pending',
        phase: 'initialization',
        progress: 0,
        modules: data.modules || [],
        options: {
          threads: 10, rate_limit: 10, timeout: 30, delay: 0.1,
          nvd_enabled: true, waf_evasion: false,
          ...(data.options || {}),
        },
        created_at: new Date().toISOString(),
        findings_count: 0,
        findings_by_severity: {},
        findings_by_tier: {},
      }
      return scan
    }
    return apiClient.post<Scan>(ENDPOINTS.scans, data)
  },

  async start(id: string)  { return apiClient.post<Scan>(ENDPOINTS.scanStart(id)) },
  async pause(id: string)  { return apiClient.post<Scan>(ENDPOINTS.scanPause(id)) },
  async resume(id: string) { return apiClient.post<Scan>(ENDPOINTS.scanResume(id)) },
  async cancel(id: string) { return apiClient.post<Scan>(ENDPOINTS.scanCancel(id)) },
  async remove(id: string) { return apiClient.delete<void>(ENDPOINTS.scan(id)) },

  async getProgress(id: string): Promise<ScanProgress> {
    if (apiClient.useMocks) return mock.progress(id)
    return apiClient.get<ScanProgress>(ENDPOINTS.scanProgress(id))
  },

  async getLogs(id: string): Promise<{ logs: string[] }> {
    if (apiClient.useMocks) {
      return { logs: [
        '[17:43:19] [info] starting scan',
        '[17:43:19] [headers] running',
        '[17:43:20] [headers] 8 findings',
        '[17:43:20] [dns] running',
        '[17:43:20] [dns] 1 finding',
        '[17:43:21] [fingerprint] running',
      ]}
    }
    return apiClient.get(ENDPOINTS.scanLogs(id))
  },

  async getModules(id: string): Promise<ModuleStatus[]> {
    if (apiClient.useMocks) return mock.modules()
    return apiClient.get<ModuleStatus[]>(ENDPOINTS.scanModules(id))
  },

  async getTarget(id: string): Promise<TargetInfo> {
    if (apiClient.useMocks) return mock.target()
    return apiClient.get<TargetInfo>(ENDPOINTS.scanTarget(id))
  },

  async validateTarget(target: string) {
    if (apiClient.useMocks) {
      const lower = target.toLowerCase().trim()
      if (!lower) return { valid: false, reason: 'empty target' }
      if (lower.endsWith('.gov') || lower.endsWith('.mil')) {
        return { valid: false, reason: 'government / military domains are forbidden' }
      }
      if (lower.includes('localhost') || lower.startsWith('127.')) {
        return { valid: false, reason: 'localhost / loopback forbidden' }
      }
      return { valid: true }
    }
    return apiClient.post<{ valid: boolean; reason?: string; warnings?: string[] }>(
      ENDPOINTS.validateTarget, { target }
    )
  },
}
