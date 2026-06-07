import { useEffect, useRef, useState } from 'react'
import type { ScanProgress } from '@app-types/scan'
import type { Finding } from '@app-types/finding'

const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL || 'ws://localhost:8000'
const USE_MOCKS   = (import.meta.env.VITE_USE_MOCKS ?? 'true') === 'true'

export interface WebSocketMessage<T = any> {
  type: string
  data: T
  timestamp: string
}

/** Generic websocket hook with auto-reconnect. */
export function useWebSocket(path: string, enabled = true) {
  const [connected, setConnected]   = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<number | null>(null)

  useEffect(() => {
    if (!enabled || USE_MOCKS) return

    const url = `${WS_BASE_URL}${path}`
    let cancelled = false

    function connect() {
      if (cancelled) return
      const sock = new WebSocket(url)
      ws.current = sock
      sock.onopen = () => setConnected(true)
      sock.onmessage = (e) => {
        try {
          setLastMessage(JSON.parse(e.data))
        } catch {
          /* ignore non-JSON */
        }
      }
      sock.onerror = () => { /* swallow */ }
      sock.onclose = () => {
        setConnected(false)
        if (!cancelled) {
          reconnectTimer.current = window.setTimeout(connect, 2000)
        }
      }
    }
    connect()

    return () => {
      cancelled = true
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [path, enabled])

  function send(payload: any) {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(payload))
    }
  }

  return { connected, lastMessage, send }
}

/** Scan progress channel + simulated progress when in mock mode. */
export function useScanWebSocket(scanId: string) {
  const { connected, lastMessage } = useWebSocket(`/ws/scans/${scanId}`, !USE_MOCKS)
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])

  // Mock-mode: tick a fake progress bar so UI feels alive
  useEffect(() => {
    if (!USE_MOCKS) return
    let pct = 5
    setProgress({
      scan_id: scanId, phase: 'reconnaissance', phase_name: 'Reconnaissance',
      percent: pct, current_module: 'tech_fingerprint',
      modules_completed: 0, modules_total: 9,
      elapsed_time: 0, estimated_remaining: 60, status: 'running',
    })
    const timer = window.setInterval(() => {
      pct = Math.min(100, pct + 5)
      setProgress((p) => p && {
        ...p,
        percent: pct,
        elapsed_time: p.elapsed_time + 2,
        estimated_remaining: Math.max(0, p.estimated_remaining - 2),
        status: pct >= 100 ? 'completed' : 'running',
      })
      if (pct >= 100) clearInterval(timer)
    }, 1500)
    return () => clearInterval(timer)
  }, [scanId])

  useEffect(() => {
    if (!lastMessage) return
    switch (lastMessage.type) {
      case 'progress':
        setProgress(lastMessage.data)
        break
      case 'finding':
        setFindings((prev) => [...prev, lastMessage.data])
        break
      case 'scan_complete':
        setProgress((p) => p && { ...p, percent: 100, status: 'completed' })
        break
    }
  }, [lastMessage])

  return { connected: USE_MOCKS ? true : connected, progress, findings }
}
