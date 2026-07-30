import { useEffect, useState } from "react"

/**
 * useDebouncedValue -- defer updates to ``value`` until ``delay`` ms
 * have passed without further change.
 *
 * V10 阶段 3.1 (2026-07-30): shared hook to replace the inline
 * ``useState + setTimeout`` pattern that AlertInboxPage, HostOnboardPage,
 * RulesPage, and (post-3.1) VulnListPage were each duplicating. Centralising
 * it here also gives us a single place to add a max-wait guarantee or
 * a leading-edge variant later, without touching the four call sites.
 *
 * ``delay`` defaults to 300ms which matches the per-keystroke filter
 * the existing AlertInboxPage (200ms) and HostOnboardPage (300ms) used.
 */
export function useDebouncedValue<T>(value: T, delay: number = 300): T {
  const [debounced, setDebounced] = useState<T>(value)

  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])

  return debounced
}