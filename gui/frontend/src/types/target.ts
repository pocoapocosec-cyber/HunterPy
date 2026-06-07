export interface Library {
  name: string
  version?: string
  vulnerable?: boolean
  cve_ids?: string[]
}

export interface TechStack {
  server?: string
  framework?: string
  cms?: string
  programming_language?: string
  database?: string
  frontend_frameworks?: string[]
  javascript_libraries?: Library[]
  cdn?: string
  analytics?: string[]
  plugins?: string[]
}

export interface DNSRecords {
  a?: string[]
  aaaa?: string[]
  mx?: Array<{ priority: number; mail_server: string } | string>
  ns?: string[]
  txt?: string[]
  cname?: string | null
}

export interface Certificate {
  subject: string
  issuer: string
  serial_number: string
  fingerprint: string
}

export interface SSLInfo {
  valid: boolean
  issuer: string
  subject: string
  valid_from?: string
  valid_to?: string
  days_remaining?: number
  version?: string
  cipher?: string
  certificate_chain?: Certificate[]
  vulnerabilities?: string[]
}

export interface WAFInfo {
  detected: boolean
  vendor?: string
  confidence?: number
  signatures?: string[]
}

export interface WHOISInfo {
  registrar?: string
  creation_date?: string
  expiration_date?: string
  updated_date?: string
  status?: string[] | string
  name_servers?: string[]
  emails?: string[] | string
  org?: string
  country?: string
}

export interface TargetInfo {
  url: string
  ip_address?: string
  hostname: string
  port: number
  protocol: string
  tech_stack?: TechStack
  dns_records?: DNSRecords
  ssl_info?: SSLInfo
  waf_detected?: WAFInfo
  rate_limit_detected?: boolean
  bot_detection?: string
  whois?: WHOISInfo
}
