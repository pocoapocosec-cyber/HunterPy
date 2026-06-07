import { useMemo, useState } from 'react'

export function usePagination<T>(items: T[], pageSize = 20) {
  const [page, setPage] = useState(0)
  const total = items.length
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const safePage = Math.min(page, pageCount - 1)
  const slice = useMemo(
    () => items.slice(safePage * pageSize, (safePage + 1) * pageSize),
    [items, safePage, pageSize]
  )
  return {
    page: safePage, pageCount, pageSize, total, slice,
    next: () => setPage((p) => Math.min(pageCount - 1, p + 1)),
    prev: () => setPage((p) => Math.max(0, p - 1)),
    goto: setPage,
  }
}
