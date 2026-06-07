import { FormProvider, useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useSearchParams } from 'react-router-dom'

import { Button } from '@components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Alert } from '@components/ui/alert'

import { TargetInput } from './TargetInput'
import { ModeSelector } from './ModeSelector'
import { ModuleSelector } from './ModuleSelector'
import { AdvancedOptions } from './AdvancedOptions'
import { ScopeFileUpload } from './ScopeFileUpload'

import { scanSchema, type ScanFormValues } from '../validation/scanSchema'
import { useNewScan } from '../hooks/useNewScan'

export function ScanConfigForm() {
  const [params] = useSearchParams()
  const presetMode = (params.get('mode') as any) || 'standard'

  const methods = useForm<ScanFormValues>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      target: '',
      mode: presetMode,
      modules: [],
      threads: 10,
      rate_limit: 10,
      timeout: 30,
      delay: 0.1,
      nvd_enabled: true,
      waf_evasion: false,
      confirm_authorized: false as any,
    },
  })

  const { handleSubmit, register, formState: { errors } } = methods
  const newScan = useNewScan()

  return (
    <Card>
      <CardHeader>
        <CardTitle>New scan</CardTitle>
      </CardHeader>
      <CardContent>
        <FormProvider {...methods}>
          <form onSubmit={handleSubmit(newScan.submit)} className="space-y-5">
            <TargetInput />
            <ModeSelector />
            <ModuleSelector />

            <div className="grid grid-cols-2 gap-3">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...register('nvd_enabled')} className="accent-brand" />
                Enable NVD CVE lookup
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" {...register('waf_evasion')} className="accent-brand" />
                WAF-aware throttling
              </label>
            </div>

            <ScopeFileUpload onFile={(_t) => {/* TODO: wire scope */}} />
            <AdvancedOptions />

            <Alert tone="warning" title="Authorization required">
              You may only scan systems you own or have explicit written
              permission to test. Unauthorized scanning is illegal.
              <label className="flex items-center gap-2 mt-2 text-sm">
                <input type="checkbox" {...register('confirm_authorized')}
                       className="accent-brand" />
                I confirm I am authorized to scan this target.
              </label>
              {errors.confirm_authorized && (
                <div className="text-xs text-severity-critical mt-1">
                  {errors.confirm_authorized.message as string}
                </div>
              )}
            </Alert>

            <Button type="submit" variant="primary" isLoading={newScan.isPending}>
              Start scan
            </Button>
          </form>
        </FormProvider>
      </CardContent>
    </Card>
  )
}
