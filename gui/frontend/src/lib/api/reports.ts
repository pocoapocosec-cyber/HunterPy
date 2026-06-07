import { apiClient } from './client'
import { ENDPOINTS } from './endpoints'
import { mock } from './mock'
import type { Report, ReportFormat } from '@app-types/report'

export const reportsAPI = {
  async list() {
    if (apiClient.useMocks) {
      const r = await mock.report()
      return { reports: [r], total: 1 }
    }
    return apiClient.get<{ reports: Report[]; total: number }>(ENDPOINTS.reports)
  },

  async getForScan(scanId: string): Promise<Report> {
    if (apiClient.useMocks) return mock.report()
    return apiClient.get<Report>(ENDPOINTS.scanReport(scanId))
  },

  async generate(scanId: string, format: ReportFormat) {
    if (apiClient.useMocks) {
      return { ...(await mock.report()), format }
    }
    return apiClient.post<Report>(ENDPOINTS.scanReport(scanId), { format })
  },

  async downloadUrl(scanId: string, format: ReportFormat): Promise<string> {
    if (apiClient.useMocks) return `/mock/report.${format}`
    return `${import.meta.env.VITE_API_BASE_URL}${ENDPOINTS.scanReport(scanId)}?format=${format}`
  },
}
