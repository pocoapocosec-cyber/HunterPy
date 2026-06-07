import { apiClient } from './client'
import { ENDPOINTS } from './endpoints'
import { mock } from './mock'
import type { Finding, FindingStatus, Severity, Tier } from '@app-types/finding'

export interface FindingListParams {
  scan_id?: string
  severity?: Severity
  tier?: Tier
  status?: FindingStatus
  limit?: number
  offset?: number
}

export const findingsAPI = {
  async list(params?: FindingListParams) {
    if (apiClient.useMocks) {
      let all = await mock.findings()
      if (params?.scan_id)  all = all.filter((f) => f.scan_id === params.scan_id)
      if (params?.severity) all = all.filter((f) => f.severity === params.severity)
      if (params?.tier)
        all = all.filter((f) => (f.classification || f.tier) === params.tier)
      if (params?.status)   all = all.filter((f) => f.status === params.status)
      return { findings: all, total: all.length }
    }
    return apiClient.get<{ findings: Finding[]; total: number }>(
      ENDPOINTS.findings, { params }
    )
  },

  async listByScan(scanId: string, params?: Omit<FindingListParams, 'scan_id'>) {
    return findingsAPI.list({ ...params, scan_id: scanId })
  },

  async get(id: string): Promise<Finding> {
    if (apiClient.useMocks) {
      const all = await mock.findings()
      const found = all.find((f) => f.id === id)
      if (!found) throw new Error(`finding ${id} not found`)
      return found
    }
    return apiClient.get<Finding>(ENDPOINTS.finding(id))
  },

  async updateStatus(id: string, status: FindingStatus, notes?: string) {
    if (apiClient.useMocks) {
      const f = await findingsAPI.get(id)
      return { ...f, status, notes }
    }
    return apiClient.patch<Finding>(ENDPOINTS.finding(id), { status, notes })
  },

  async addTags(id: string, tags: string[]) {
    if (apiClient.useMocks) {
      const f = await findingsAPI.get(id)
      return { ...f, tags: [...new Set([...(f.tags || []), ...tags])] }
    }
    return apiClient.post<Finding>(ENDPOINTS.findingTags(id), { tags })
  },

  async runExploit(id: string) {
    if (apiClient.useMocks) {
      return {
        success: false,
        output: 'Mock mode: exploit execution disabled for safety.',
        timestamp: new Date().toISOString(),
      }
    }
    return apiClient.post<{ success: boolean; output: string; timestamp: string }>(
      ENDPOINTS.findingExploit(id)
    )
  },
}
