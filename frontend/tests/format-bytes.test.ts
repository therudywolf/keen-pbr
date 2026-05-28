import { describe, expect, test } from "bun:test"

import { formatBytes, formatCount } from "../src/lib/format-bytes"

describe("formatBytes", () => {
  test("shows whole bytes below 1 KB", () => {
    expect(formatBytes(0)).toBe("0 B")
    expect(formatBytes(512)).toBe("512 B")
    expect(formatBytes(1023)).toBe("1023 B")
  })

  test("scales into binary units and trims trailing .0", () => {
    expect(formatBytes(1024)).toBe("1 KB")
    expect(formatBytes(1536)).toBe("1.5 KB")
    expect(formatBytes(1024 * 1024)).toBe("1 MB")
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1 GB")
  })

  test("keeps one decimal under 100 and rounds whole at/above 100", () => {
    expect(formatBytes(1024 * 1024 * 1.25)).toBe("1.3 MB")
    expect(formatBytes(1024 * 150)).toBe("150 KB")
  })

  test("collapses negative and non-finite input to 0 B", () => {
    expect(formatBytes(-5)).toBe("0 B")
    expect(formatBytes(Number.NaN)).toBe("0 B")
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe("0 B")
  })
})

describe("formatCount", () => {
  test("groups thousands with a stable separator", () => {
    expect(formatCount(0)).toBe("0")
    expect(formatCount(1234)).toBe("1,234")
    expect(formatCount(1234567)).toBe("1,234,567")
  })

  test("rounds fractional input and guards non-finite values", () => {
    expect(formatCount(1234.6)).toBe("1,235")
    expect(formatCount(Number.NaN)).toBe("0")
  })
})
