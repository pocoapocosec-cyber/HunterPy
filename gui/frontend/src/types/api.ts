export interface Paginated<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface APIError {
  detail: string
  status_code?: number
  errors?: Record<string, string[]>
}
