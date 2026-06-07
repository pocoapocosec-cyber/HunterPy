export const ROUTES = {
  dashboard:    '/',
  scans:        '/scans',
  newScan:      '/scans/new',
  scanDetail:   (id: string) => `/scans/${id}`,
  findings:     '/findings',
  findingDetail: (id: string) => `/findings/${id}`,
  reports:      '/reports',
  settings:     '/settings',
  login:        '/login',
} as const
