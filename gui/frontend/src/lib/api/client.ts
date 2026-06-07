import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const USE_MOCKS    = (import.meta.env.VITE_USE_MOCKS ?? 'true') === 'true'

class APIClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' },
    })

    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('auth_token')
      if (token) config.headers.Authorization = `Bearer ${token}`
      return config
    })

    this.client.interceptors.response.use(
      (r) => r,
      async (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('auth_token')
          if (window.location.pathname !== '/login') {
            window.location.href = '/login'
          }
        }
        return Promise.reject(error)
      }
    )
  }

  get useMocks() { return USE_MOCKS }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const { data } = await this.client.get<T>(url, config)
    return data
  }
  async post<T>(url: string, body?: any, config?: AxiosRequestConfig): Promise<T> {
    const { data } = await this.client.post<T>(url, body, config)
    return data
  }
  async put<T>(url: string, body?: any, config?: AxiosRequestConfig): Promise<T> {
    const { data } = await this.client.put<T>(url, body, config)
    return data
  }
  async patch<T>(url: string, body?: any, config?: AxiosRequestConfig): Promise<T> {
    const { data } = await this.client.patch<T>(url, body, config)
    return data
  }
  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const { data } = await this.client.delete<T>(url, config)
    return data
  }
}

export const apiClient = new APIClient()
