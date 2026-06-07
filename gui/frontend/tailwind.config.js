/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       { DEFAULT: '#0f172a', soft: '#1e293b', deep: '#0b1220' },
        line:     '#334155',
        text:     { DEFAULT: '#e5e7eb', muted: '#94a3b8' },
        brand:    '#06b6d4',
        severity: {
          critical: '#dc2626',
          high:     '#ea580c',
          medium:   '#d97706',
          low:      '#16a34a',
          info:     '#6b7280',
        },
        tier: {
          interesting: '#dc2626',
          common:      '#d97706',
          falsealarm:  '#16a34a',
        },
      },
      keyframes: {
        'scan-pulse': {
          '0%, 100%': { opacity: 1 },
          '50%':      { opacity: 0.5 },
        },
        shimmer: {
          '0%':   { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      animation: {
        'scan-pulse': 'scan-pulse 1.6s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        shimmer: 'shimmer 1.8s linear infinite',
      },
    },
  },
  plugins: [],
}
