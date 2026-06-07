import { useStartScan } from '@features/scans/hooks/useStartScan'
import type { ScanFormValues } from '../validation/scanSchema'

export function useNewScan() {
  const mutation = useStartScan()
  function submit(values: ScanFormValues) {
    mutation.mutate({
      target: values.target,
      mode: values.mode,
      modules: values.modules,
      options: {
        threads: values.threads,
        rate_limit: values.rate_limit,
        timeout: values.timeout,
        delay: values.delay,
        nvd_enabled: values.nvd_enabled,
        waf_evasion: values.waf_evasion,
        proxy: values.proxy,
        user_agent: values.user_agent,
        auth_url: values.auth_url,
        username_list: values.username_list,
        password_list: values.password_list,
      },
    })
  }
  return { submit, ...mutation }
}
