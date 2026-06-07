import { useEffect, useRef } from 'react'

export function useInfiniteScroll(onHit: () => void, enabled = true) {
  const ref = useRef<HTMLDivElement | null>(null)
  useEffect(() => {
    if (!enabled || !ref.current) return
    const el = ref.current
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) onHit()
    }, { rootMargin: '200px' })
    obs.observe(el)
    return () => obs.disconnect()
  }, [onHit, enabled])
  return ref
}
