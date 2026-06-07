export const ENDPOINTS = {
  scans:           '/api/scans',
  scan:            (id: string) => `/api/scans/${id}`,
  scanStart:       (id: string) => `/api/scans/${id}/start`,
  scanPause:       (id: string) => `/api/scans/${id}/pause`,
  scanResume:      (id: string) => `/api/scans/${id}/resume`,
  scanCancel:      (id: string) => `/api/scans/${id}/cancel`,
  scanProgress:    (id: string) => `/api/scans/${id}/progress`,
  scanLogs:        (id: string) => `/api/scans/${id}/logs`,
  scanModules:     (id: string) => `/api/scans/${id}/modules`,
  scanFindings:    (id: string) => `/api/scans/${id}/findings`,
  scanTarget:      (id: string) => `/api/scans/${id}/target`,
  scanReport:      (id: string) => `/api/scans/${id}/report`,
  scanExportFindings: (id: string) => `/api/scans/${id}/findings/export`,
  validateTarget:  '/api/scans/validate-target',

  findings:        '/api/findings',
  finding:         (id: string) => `/api/findings/${id}`,
  findingExploit:  (id: string) => `/api/findings/${id}/exploit`,
  findingTags:     (id: string) => `/api/findings/${id}/tags`,

  reports:         '/api/reports',
  report:          (id: string) => `/api/reports/${id}`,
  reportTemplates: '/api/reports/templates',

  settings:        '/api/settings',
  tools:           '/api/tools',

  auth:            '/api/auth/login',
  me:              '/api/auth/me',
} as const
