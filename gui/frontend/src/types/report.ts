import type { Finding, Severity, Tier } from './finding'
import type { TargetInfo } from './target'

export type ReportFormat = 'html' | 'pdf' | 'json' | 'markdown' | 'csv' | 'xml'

export interface ExecutiveSummary {
  overview: string
  risk_rating: 'critical' | 'high' | 'medium' | 'low'
  key_findings: string[]
  recommendations: string[]
  impact_assessment: string
}

export interface ReportStatistics {
  total_findings: number
  by_severity: Record<Severity, number>
  by_tier: Record<Tier, number>
  by_type: Record<string, number>
  by_module: Record<string, number>
  scan_duration: number
  modules_run: number
  requests_sent?: number
  coverage?: {
    endpoints_discovered: number
    parameters_tested: number
    forms_found: number
  }
}

export interface Report {
  id: string
  scan_id: string
  format: ReportFormat
  generated_at: string
  title: string
  description?: string
  executive_summary?: ExecutiveSummary
  findings: Finding[]
  statistics: ReportStatistics
  target_info?: TargetInfo
  file_path?: string
  file_size?: number
  download_url?: string
}

export interface ReportSection {
  id: string
  title: string
  enabled: boolean
  order: number
  content_type: 'findings' | 'statistics' | 'target_info' | 'custom'
}

export interface ReportTemplate {
  id: string
  name: string
  description: string
  format: ReportFormat
  sections: ReportSection[]
  customizable: boolean
}
