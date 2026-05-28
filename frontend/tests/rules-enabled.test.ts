import { describe, expect, test } from "bun:test"

import {
  emptyRouteRuleDraft,
  normalizeRouteRuleDraft,
  setRouteRuleEnabled,
  toRouteRuleDraft,
} from "../src/pages/routing-rules-utils"

describe("routing rule enabled helpers", () => {
  test("new route rule drafts default to enabled", () => {
    expect(emptyRouteRuleDraft.enabled).toBe(true)
    expect(normalizeRouteRuleDraft(emptyRouteRuleDraft).enabled).toBe(true)
  })

  test("route rule draft preserves disabled state and defaults missing state to enabled", () => {
    expect(
      toRouteRuleDraft({
        enabled: false,
        list: ["ads"],
        outbound: "vpn",
      }).enabled
    ).toBe(false)

    expect(
      toRouteRuleDraft({
        list: ["ads"],
        outbound: "vpn",
      }).enabled
    ).toBe(true)
  })

  test("setRouteRuleEnabled updates only the targeted rule", () => {
    const rules = [
      { list: ["one"], outbound: "vpn" },
      { enabled: false, list: ["two"], outbound: "wan" },
    ]

    expect(setRouteRuleEnabled(rules, 1, true)).toEqual([
      { list: ["one"], outbound: "vpn" },
      { enabled: true, list: ["two"], outbound: "wan" },
    ])
  })
})
