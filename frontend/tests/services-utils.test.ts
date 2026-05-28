import { describe, expect, test } from "bun:test"

import type { RouteRule } from "../src/api/generated/model/routeRule"
import {
  findIpv4LeakRow,
  getServiceEntryCount,
  getServiceLeakCheckTarget,
  getServiceOutbound,
  reassignServiceOutbound,
} from "../src/pages/services-utils"

describe("getServiceOutbound", () => {
  test("returns outbound of first enabled rule referencing the service", () => {
    const rules: RouteRule[] = [
      { enabled: false, list: ["youtube"], outbound: "vpn" },
      { list: ["youtube"], outbound: "wan" },
    ]

    expect(getServiceOutbound(rules, "youtube")).toBe("wan")
  })

  test("returns undefined when no enabled rule references the service", () => {
    const rules: RouteRule[] = [
      { enabled: false, list: ["youtube"], outbound: "vpn" },
    ]

    expect(getServiceOutbound(rules, "youtube")).toBeUndefined()
    expect(getServiceOutbound(rules, "netflix")).toBeUndefined()
  })
})

describe("reassignServiceOutbound", () => {
  test("moves a service into the first enabled rule of the target outbound", () => {
    const rules: RouteRule[] = [
      { list: ["youtube", "ads"], outbound: "vpn" },
      { list: ["work"], outbound: "wan" },
    ]

    expect(reassignServiceOutbound(rules, "youtube", "wan")).toEqual([
      { list: ["ads"], outbound: "vpn" },
      { list: ["work", "youtube"], outbound: "wan" },
    ])
  })

  test("drops a rule only when removing the service empties its list", () => {
    const rules: RouteRule[] = [
      { list: ["youtube"], outbound: "vpn" },
      { list: ["work"], outbound: "wan" },
    ]

    expect(reassignServiceOutbound(rules, "youtube", "wan")).toEqual([
      { list: ["work", "youtube"], outbound: "wan" },
    ])
  })

  test("appends a new rule when no enabled target rule exists", () => {
    const rules: RouteRule[] = [{ list: ["youtube"], outbound: "vpn" }]

    expect(reassignServiceOutbound(rules, "youtube", "wan")).toEqual([
      { enabled: true, list: ["youtube"], outbound: "wan" },
    ])
  })

  test("does not target a disabled rule of the target outbound", () => {
    const rules: RouteRule[] = [
      { list: ["youtube"], outbound: "vpn" },
      { enabled: false, list: ["work"], outbound: "wan" },
    ]

    expect(reassignServiceOutbound(rules, "youtube", "wan")).toEqual([
      { enabled: false, list: ["work"], outbound: "wan" },
      { enabled: true, list: ["youtube"], outbound: "wan" },
    ])
  })

  test("preserves non-list rules and other fields", () => {
    const rules: RouteRule[] = [
      { list: ["youtube"], outbound: "vpn", proto: "tcp" },
      { dest_addr: "10.0.0.0/8", outbound: "wan" },
    ]

    expect(reassignServiceOutbound(rules, "youtube", "wan")).toEqual([
      { dest_addr: "10.0.0.0/8", outbound: "wan", list: ["youtube"] },
    ])
  })
})

describe("getServiceEntryCount", () => {
  test("sums inline domains and ip_cidrs", () => {
    expect(
      getServiceEntryCount({
        domains: ["a.com", "b.com"],
        ip_cidrs: ["1.2.3.0/24"],
      })
    ).toBe(3)
  })

  test("returns undefined for url/file-backed lists with no inline entries", () => {
    expect(getServiceEntryCount({ url: "https://example.com/list" })).toBeUndefined()
    expect(getServiceEntryCount({})).toBeUndefined()
  })
})

describe("getServiceLeakCheckTarget", () => {
  test("prefers the first domain-like entry over a numeric IP", () => {
    expect(
      getServiceLeakCheckTarget({
        ip_cidrs: ["1.2.3.4"],
        domains: ["example.com"],
      })
    ).toBe("example.com")
  })

  test("falls back to the first entry when none look like domains", () => {
    expect(getServiceLeakCheckTarget({ ip_cidrs: ["8.8.8.8", "1.1.1.1"] })).toBe(
      "8.8.8.8"
    )
  })

  test("returns undefined when empty", () => {
    expect(getServiceLeakCheckTarget({})).toBeUndefined()
  })
})

describe("findIpv4LeakRow", () => {
  test("finds the first failing IPv4 row and ignores IPv6 and ok rows", () => {
    const rows = [
      { ip: "2001:db8::1", ok: false, actual_outbound: "wan" },
      { ip: "8.8.8.8", ok: true, actual_outbound: "vpn" },
      { ip: "1.1.1.1", ok: false, actual_outbound: "rostelecom" },
    ]

    expect(findIpv4LeakRow(rows)).toEqual({
      ip: "1.1.1.1",
      ok: false,
      actual_outbound: "rostelecom",
    })
  })

  test("returns undefined when all IPv4 rows are ok", () => {
    const rows = [{ ip: "8.8.8.8", ok: true, actual_outbound: "vpn" }]

    expect(findIpv4LeakRow(rows)).toBeUndefined()
  })
})
