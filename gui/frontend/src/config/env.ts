export const env = {
  apiBase: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  wsBase:  import.meta.env.VITE_WS_BASE_URL  || 'ws://localhost:8000',
  useMocks: (import.meta.env.VITE_USE_MOCKS ?? 'true') === 'true',
}
