import { describe, expect, test } from "bun:test"

import type { RouteRule } from "../src/api/generated/model/routeRule"
import type { RoutingTestResponse } from "../src/api/generated/model/routingTestResponse"
import {
  collectLeakingDomains,
  evaluateLeakCheck,
  evaluateServiceScan,
  findIpv4LeakRow,
  getServiceDomainCount,
  getServiceEntryCount,
  getServiceLeakCheckTarget,
  getServiceOutbound,
  reassignServiceOutbound,
  runServiceLeakCheck,
  runServiceScan,
  runWithConcurrency,
} from "../src/pages/services-utils"

function buildRoutingTestResponse(
  results: RoutingTestResponse["results"],
): RoutingTestResponse {
  return {
    target: "example.com",
    is_domain: true,
    resolved_ips: results.map((row) => row.ip),
    warnings: [],
    no_matching_rule: false,
    rule_diagnostics: [],
    results,
  }
}

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

describe("evaluateLeakCheck", () => {
  test("reports leaking with the failing IPv4 row's actual outbound", () => {
    const response = buildRoutingTestResponse([
      { ip: "8.8.8.8", ok: false, actual_outbound: "rostelecom", expected_outbound: "forestserver_ru" },
    ])

    expect(evaluateLeakCheck(response)).toEqual({
      status: "leaking",
      actualOutbound: "rostelecom",
    })
  })

  test("reports ok when no IPv4 row leaks", () => {
    const response = buildRoutingTestResponse([
      { ip: "8.8.8.8", ok: true, actual_outbound: "forestserver_ru", expected_outbound: "forestserver_ru" },
    ])

    expect(evaluateLeakCheck(response)).toEqual({ status: "ok" })
  })
})

describe("runServiceLeakCheck", () => {
  test("maps a 200 response into a verdict", async () => {
    const response = buildRoutingTestResponse([
      { ip: "1.1.1.1", ok: false, actual_outbound: "rostelecom", expected_outbound: "forestserver_ru" },
    ])

    const verdict = await runServiceLeakCheck("example.com", async () => ({
      status: 200,
      data: response,
    }))

    expect(verdict).toEqual({ status: "leaking", actualOutbound: "rostelecom" })
  })

  test("treats a non-200 status as an error verdict", async () => {
    const verdict = await runServiceLeakCheck("example.com", async () => ({
      status: 400,
      data: { error: "bad target" },
    }))

    expect(verdict).toEqual({ status: "error" })
  })

  test("treats a thrown request as an error verdict", async () => {
    const verdict = await runServiceLeakCheck("example.com", async () => {
      throw new Error("network down")
    })

    expect(verdict).toEqual({ status: "error" })
  })
})

describe("evaluateServiceScan", () => {
  test("captures both expected and actual outbound of the failing IPv4 row", () => {
    const response = buildRoutingTestResponse([
      {
        ip: "8.8.8.8",
        ok: false,
        actual_outbound: "rostelecom",
        expected_outbound: "forestserver_ru",
      },
    ])

    expect(evaluateServiceScan(response)).toEqual({
      status: "leaking",
      expectedOutbound: "forestserver_ru",
      actualOutbound: "rostelecom",
    })
  })

  test("reports ok when no IPv4 row leaks", () => {
    const response = buildRoutingTestResponse([
      {
        ip: "8.8.8.8",
        ok: true,
        actual_outbound: "forestserver_ru",
        expected_outbound: "forestserver_ru",
      },
    ])

    expect(evaluateServiceScan(response)).toEqual({ status: "ok" })
  })
})

describe("runServiceScan", () => {
  test("maps a 200 response into a rich leaking verdict", async () => {
    const response = buildRoutingTestResponse([
      {
        ip: "1.1.1.1",
        ok: false,
        actual_outbound: "rostelecom",
        expected_outbound: "forestserver_ru",
      },
    ])

    const verdict = await runServiceScan("example.com", async () => ({
      status: 200,
      data: response,
    }))

    expect(verdict).toEqual({
      status: "leaking",
      expectedOutbound: "forestserver_ru",
      actualOutbound: "rostelecom",
    })
  })

  test("treats a non-200 status as an error verdict", async () => {
    const verdict = await runServiceScan("example.com", async () => ({
      status: 500,
      data: { error: "boom" },
    }))

    expect(verdict).toEqual({ status: "error" })
  })

  test("treats a thrown request as an error verdict", async () => {
    const verdict = await runServiceScan("example.com", async () => {
      throw new Error("network down")
    })

    expect(verdict).toEqual({ status: "error" })
  })
})

describe("getServiceDomainCount", () => {
  test("counts non-empty inline domains and ignores ip_cidrs", () => {
    expect(
      getServiceDomainCount({
        domains: ["a.com", "b.com", "  ", ""],
        ip_cidrs: ["1.2.3.0/24"],
      })
    ).toBe(2)
  })

  test("returns 0 for lists with no inline domains", () => {
    expect(getServiceDomainCount({ ip_cidrs: ["1.2.3.0/24"] })).toBe(0)
    expect(getServiceDomainCount({})).toBe(0)
  })
})

describe("collectLeakingDomains", () => {
  test("gathers deduped, sorted domains from leaking services only", () => {
    const leakChecks = {
      youtube: { status: "leaking", actualOutbound: "rostelecom" } as const,
      netflix: { status: "ok" } as const,
      discord: { status: "leaking", actualOutbound: "rostelecom" } as const,
      vimeo: { status: "loading" } as const,
    }
    const lists = {
      youtube: { domains: ["youtube.com", "ytimg.com"] },
      netflix: { domains: ["netflix.com"] },
      discord: { domains: ["discord.com", "youtube.com"] },
    }

    expect(collectLeakingDomains(leakChecks, lists)).toEqual([
      "discord.com",
      "youtube.com",
      "ytimg.com",
    ])
  })

  test("skips services missing from lists and those without inline domains", () => {
    const leakChecks = {
      ipset_only: { status: "leaking", actualOutbound: "wan" } as const,
      ghost: { status: "leaking", actualOutbound: "wan" } as const,
    }
    const lists = {
      ipset_only: { ip_cidrs: ["1.2.3.0/24"] },
    }

    expect(collectLeakingDomains(leakChecks, lists)).toEqual([])
  })

  test("returns an empty array when nothing is leaking", () => {
    const leakChecks = {
      youtube: { status: "ok" } as const,
    }
    const lists = {
      youtube: { domains: ["youtube.com"] },
    }

    expect(collectLeakingDomains(leakChecks, lists)).toEqual([])
  })
})

describe("runWithConcurrency", () => {
  test("processes every item and reports each result", async () => {
    const items = [1, 2, 3, 4, 5]
    const processed: number[] = []
    let results = 0

    await runWithConcurrency(
      items,
      2,
      async (item) => {
        processed.push(item)
      },
      { onResult: () => (results += 1) },
    )

    expect(processed.sort((a, b) => a - b)).toEqual(items)
    expect(results).toBe(items.length)
  })

  test("never exceeds the concurrency limit in flight", async () => {
    const items = Array.from({ length: 10 }, (_, index) => index)
    let inFlight = 0
    let peak = 0

    await runWithConcurrency(items, 3, async () => {
      inFlight += 1
      peak = Math.max(peak, inFlight)
      await Promise.resolve()
      inFlight -= 1
    })

    expect(peak).toBeLessThanOrEqual(3)
  })

  test("stops launching new work once shouldStop returns true", async () => {
    const items = [1, 2, 3, 4, 5, 6]
    const processed: number[] = []
    let stop = false

    await runWithConcurrency(
      items,
      1,
      async (item) => {
        processed.push(item)
        if (item === 2) {
          stop = true
        }
      },
      { shouldStop: () => stop },
    )

    // With concurrency 1 and a stop after item 2, items 3+ never start.
    expect(processed).toEqual([1, 2])
  })
})
