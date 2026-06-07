export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Tier = 'INTERESTING' | 'COMMON' | 'FALSE_ALARM'
export type FindingStatus = 'new' | 'triaged' | 'confirmed' | 'false_positive' | 'fixed'

export interface HTTPRequest {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}

export interface HTTPResponse {
  status_code: number
  headers: Record<string, string>
  body?: string
  time_taken: number
}

export interface Evidence {
  request?: HTTPRequest
  response?: HTTPResponse
  diff?: string
  screenshot?: string
  [key: string]: any
}

export interface ExploitResult {
  success: boolean
  output: string
  timestamp: string
}

export interface ProofOfConcept {
  title: string
  finding_type: string
  description: string
  steps: string[]
  sample_command?: string
  remediation: string
  references: string[]
  exploit_result?: ExploitResult
}

export interface Remediation {
  summary: string
  detailed_steps: string[]
  code_example?: string
  difficulty: 'easy' | 'medium' | 'hard'
  estimated_time: string
}

export interface Finding {
  id: string
  scan_id: string

  type: string
  severity: Severity
  classification?: Tier            // server uses 'classification'
  tier?: Tier                      // alias
  classification_confidence?: number
  classification_reason?: string
  confidence?: number
  score?: number

  title: string
  description?: string
  details?: string
  url: string
  module: string
  parameter?: string
  payload?: string

  evidence?: Evidence
  poc?: ProofOfConcept

  cve_ids?: string[]
  cwe_ids?: string[]
  cvss_score?: number
  cvss?: number

  discovered_at?: string
  created_at?: string

  remediation?: Remediation | string
  references?: string[]

  status?: FindingStatus
  notes?: string
  tags?: string[]
}
