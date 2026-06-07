import { z } from 'zod'

export const scanSchema = z.object({
  target: z.string().min(1, 'Target is required')
    .refine((v) => !/^https?:\/\/(localhost|127\.|0\.0\.0\.0|::1)/i.test(v),
            'Localhost / loopback targets are forbidden')
    .refine((v) => !/\.gov$|\.mil$/i.test(v.replace(/^https?:\/\//i, '').split('/')[0]),
            'Government / military domains are forbidden'),
  mode: z.enum(['passive', 'quick', 'standard', 'full', 'stealth', 'custom']),
  modules: z.array(z.string()).optional(),
  threads: z.coerce.number().min(1).max(64).default(10),
  rate_limit: z.coerce.number().min(1).max(200).default(10),
  timeout: z.coerce.number().min(1).max(600).default(30),
  delay: z.coerce.number().min(0).max(60).default(0.1),
  nvd_enabled: z.boolean().default(true),
  waf_evasion: z.boolean().default(false),
  proxy: z.string().optional(),
  user_agent: z.string().optional(),
  cookies: z.string().optional(),
  auth_url: z.string().optional(),
  username_list: z.string().optional(),
  password_list: z.string().optional(),
  confirm_authorized: z.literal(true, {
    errorMap: () => ({ message: 'You must confirm authorization to proceed.' }),
  }),
})

export type ScanFormValues = z.infer<typeof scanSchema>
