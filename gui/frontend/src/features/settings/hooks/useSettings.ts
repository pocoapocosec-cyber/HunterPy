import { useLocalStorage } from '@/lib/hooks/useLocalStorage'

export interface AppSettings {
  defaultMode: string
  defaultThreads: number
  defaultRateLimit: number
  nvdApiKey: string
  notificationsEnabled: boolean
}
const DEFAULT: AppSettings = {
  defaultMode: 'standard',
  defaultThreads: 10,
  defaultRateLimit: 10,
  nvdApiKey: '',
  notificationsEnabled: true,
}
export function useSettings() {
  return useLocalStorage<AppSettings>('hunterpy_settings', DEFAULT)
}
