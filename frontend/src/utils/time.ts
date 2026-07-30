/**
 * Time formatting utilities. The backend stores all timestamps as
 * UTC ISO 8601; we render them to the operator in Asia/Shanghai.
 *
 * 2026-07-29 UX upgrade: replace all ad-hoc `v?.slice(0, 19)` /
 * `new Date(v).toLocaleString()` calls with formatBeijing so the
 * whole app speaks one timezone and one relative-label vocabulary.
 */

const BEIJING_OFFSET_MIN = 8 * 60

/** Convert any timestamp (ISO string / Date / number) to a Date in Beijing time. */
export function toBeijing(input: string | number | Date | null | undefined): Date | null {
  if (input == null || input === "") return null
  const d = input instanceof Date ? input : new Date(input)
  if (Number.isNaN(d.getTime())) return null
  // Compute Beijing wall-clock components from the UTC instant.
  const utcMs = d.getTime()
  const beijing = new Date(utcMs + BEIJING_OFFSET_MIN * 60_000)
  return beijing
}

const pad2 = (n: number) => (n < 10 ? `0${n}` : `${n}`)

/**
 * Human-friendly relative time (Beijing):
 *   HH:MM         today
 *   昨天 HH:MM    yesterday
 *   MM-DD HH:MM   same year
 *   YYYY-MM-DD HH:MM  older
 *
 * Returns "-" for null / empty / invalid input.
 */
export function formatBeijing(input: string | number | Date | null | undefined): string {
  const bj = toBeijing(input)
  if (!bj) return "-"
  const now = toBeijing(new Date())
  if (!now) return formatBeijingFull(input)
  // Compare Beijing y/m/d
  const sameDay =
    bj.getUTCFullYear() === now.getUTCFullYear() &&
    bj.getUTCMonth() === now.getUTCMonth() &&
    bj.getUTCDate() === now.getUTCDate()
  if (sameDay) {
    return `${pad2(bj.getUTCHours())}:${pad2(bj.getUTCMinutes())}`
  }
  const yesterday = new Date(now)
  yesterday.setUTCDate(now.getUTCDate() - 1)
  const isYesterday =
    bj.getUTCFullYear() === yesterday.getUTCFullYear() &&
    bj.getUTCMonth() === yesterday.getUTCMonth() &&
    bj.getUTCDate() === yesterday.getUTCDate()
  if (isYesterday) {
    return `昨天 ${pad2(bj.getUTCHours())}:${pad2(bj.getUTCMinutes())}`
  }
  const sameYear = bj.getUTCFullYear() === now.getUTCFullYear()
  if (sameYear) {
    return `${pad2(bj.getUTCMonth() + 1)}-${pad2(bj.getUTCDate())} ${pad2(bj.getUTCHours())}:${pad2(bj.getUTCMinutes())}`
  }
  return formatBeijingFull(input)
}

/** Full local-time format: YYYY-MM-DD HH:MM:SS in Beijing. */
export function formatBeijingFull(input: string | number | Date | null | undefined): string {
  const bj = toBeijing(input)
  if (!bj) return "-"
  return (
    `${bj.getUTCFullYear()}-${pad2(bj.getUTCMonth() + 1)}-${pad2(bj.getUTCDate())} ` +
    `${pad2(bj.getUTCHours())}:${pad2(bj.getUTCMinutes())}:${pad2(bj.getUTCSeconds())}`
  )
}
