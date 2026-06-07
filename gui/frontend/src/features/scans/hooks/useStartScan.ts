import { useMutation, useQueryClient } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/config/routes'
import { useToast } from '@components/ui/toast'

export function useStartScan() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  return useMutation({
    mutationFn: scansAPI.create,
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      toast.push(`Scan ${scan.id} queued for ${scan.target}`, 'success')
      nav(ROUTES.scanDetail(scan.id))
    },
    onError: (e: any) => {
      toast.push(e?.response?.data?.detail || e?.message || 'Failed to create scan', 'error')
    },
  })
}
