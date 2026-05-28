import type { ListConfig } from "@/api/generated/model/listConfig"
import type { RouteRule } from "@/api/generated/model/routeRule"

/** A route rule counts as enabled unless it is explicitly `false`. */
function isRuleEnabled(rule: RouteRule): boolean {
  return rule.enabled ?? true
}

/**
 * Returns the outbound a service currently routes through: scan rules in order
 * and pick the first ENABLED rule whose `list` includes the service. Returns
 * undefined when no enabled rule references the service.
 */
export function getServiceOutbound(
  rules: RouteRule[],
  service: string
): string | undefined {
  for (const rule of rules) {
    if (isRuleEnabled(rule) && (rule.list ?? []).includes(service)) {
      return rule.outbound
    }
  }

  return undefined
}

/**
 * Reassigns a single service (list name) to `targetOutbound`.
 *
 * - Removes `service` from every rule's `list`.
 * - Drops a rule only if its `list` became empty *as a result of* this removal
 *   (rules that match purely on addr/port and never had a list are preserved).
 * - Adds `service` to the FIRST enabled rule whose `outbound === targetOutbound`;
 *   if none exists, appends `{ enabled: true, list: [service], outbound }`.
 * - Preserves rule order and every other field.
 */
export function reassignServiceOutbound(
  rules: RouteRule[],
  service: string,
  targetOutbound: string
): RouteRule[] {
  const withoutService: RouteRule[] = []

  for (const rule of rules) {
    const originalList = rule.list ?? []
    const hadService = originalList.includes(service)

    if (!hadService) {
      withoutService.push(rule)
      continue
    }

    const nextList = originalList.filter((name) => name !== service)
    // Drop the rule only when removing this service emptied its list.
    if (nextList.length === 0) {
      continue
    }

    withoutService.push({ ...rule, list: nextList })
  }

  const targetIndex = withoutService.findIndex(
    (rule) => isRuleEnabled(rule) && rule.outbound === targetOutbound
  )

  if (targetIndex === -1) {
    return [
      ...withoutService,
      { enabled: true, list: [service], outbound: targetOutbound },
    ]
  }

  return withoutService.map((rule, index) =>
    index === targetIndex
      ? { ...rule, list: [...(rule.list ?? []), service] }
      : rule
  )
}

/** Number of inline entries (domains + IP CIDRs) for a list, or undefined for URL/file-backed lists. */
export function getServiceEntryCount(list: ListConfig): number | undefined {
  const domains = list.domains ?? []
  const ipCidrs = list.ip_cidrs ?? []

  if (domains.length === 0 && ipCidrs.length === 0) {
    return undefined
  }

  return domains.length + ipCidrs.length
}

/**
 * Picks the entry to probe for a leak check: the first domain-like entry (one
 * containing a letter, e.g. a hostname) so DNS resolution is meaningful, else
 * the first available entry.
 */
export function getServiceLeakCheckTarget(list: ListConfig): string | undefined {
  const entries = [...(list.domains ?? []), ...(list.ip_cidrs ?? [])]
  const domainLike = entries.find((entry) => /[a-z]/i.test(entry))

  return domainLike ?? entries[0]
}

/** Returns the first IPv4 result row that failed (expected !== actual outbound), if any. */
export function findIpv4LeakRow<
  T extends { ip: string; ok: boolean; actual_outbound: string },
>(results: T[]): T | undefined {
  return results.find((result) => isIpv4(result.ip) && !result.ok)
}

function isIpv4(ip: string): boolean {
  // IPv4 dotted-quad; IPv6 contains ":" so this naturally excludes it.
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)
}
