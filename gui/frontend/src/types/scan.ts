export type ScanStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type ScanMode = 'passive' | 'quick' | 'standard' | 'full' | 'stealth' | 'custom'

export type ScanPhase =
  | 'initialization'
  | 'reconnaissance'
  | 'active_scanning'
  | 'targeted_testing'
  | 'auth_testing'
  | 'hash_cracking'
  | 'reporting'

export interface ScanOptions {
  threads: number
  rate_limit: number
  timeout: number
  delay: number
  user_agent?: string
  proxy?: string
  auth_url?: string
  username_list?: string
  password_list?: string
  custom_headers?: Record<string, string>
  nvd_enabled: boolean
  waf_evasion: boolean
}

export interface Scan {
  id: string
  target: string
  mode: ScanMode
  status: ScanStatus
  phase: ScanPhase
  progress: number

  modules: string[]
  options: ScanOptions
  scope_file?: string

  created_at: string
  started_at?: string
  completed_at?: string

  findings_count: number
  findings_by_severity: Record<string, number>
  findings_by_tier: Record<string, number>

  duration?: number
  error?: string
}

export interface ScanProgress {
  scan_id: string
  phase: ScanPhase
  phase_name: string
  percent: number
  current_module?: string
  modules_completed: number
  modules_total: number
  elapsed_time: number
  estimated_remaining: number
  status: ScanStatus
}

export interface ModuleStatus {
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  progress: number
  findings_count: number
  started_at?: string
  completed_at?: string
  error?: string
}
