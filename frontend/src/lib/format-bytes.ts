/**
 * Humanizes a byte count into a compact unit string (B / KB / MB / GB / TB / PB).
 *
 * Uses binary (1024) units to match how routers report traffic counters. Values
 * below 1 KB are shown without decimals; larger values keep up to one decimal
 * place and trim a trailing `.0` so totals read cleanly (e.g. `12 MB`, `1.5 GB`).
 * Negative or non-finite inputs collapse to `0 B`.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B"
  }

  const units = ["B", "KB", "MB", "GB", "TB", "PB"]
  let value = bytes
  let unitIndex = 0

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }

  if (unitIndex === 0) {
    // Whole bytes — never show a fractional byte.
    return `${Math.round(value)} ${units[unitIndex]}`
  }

  const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10
  const text = Number.isInteger(rounded) ? `${rounded}` : rounded.toFixed(1)

  return `${text} ${units[unitIndex]}`
}

/**
 * Humanizes a (possibly large) integer count with thousands separators using a
 * fixed `en-US` grouping so packet counts read the same regardless of locale.
 */
export function formatCount(count: number): string {
  if (!Number.isFinite(count)) {
    return "0"
  }

  return Math.round(count).toLocaleString("en-US")
}
