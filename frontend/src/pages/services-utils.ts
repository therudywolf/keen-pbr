import type { ListConfig } from "@/api/generated/model/listConfig"
import type { RouteRule } from "@/api/generated/model/routeRule"
import type { RoutingTestResponse } from "@/api/generated/model/routingTestResponse"

/** Verdict shown on a service row's leak badge. */
export type LeakCheckState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ok" }
  | { status: "leaking"; actualOutbound: string }

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

/** Maps a routing-test response into a leak verdict for a service row. */
export function evaluateLeakCheck(
  diagnostics: RoutingTestResponse
): LeakCheckState {
  const leakRow = findIpv4LeakRow(diagnostics.results)

  return leakRow
    ? { status: "leaking", actualOutbound: leakRow.actual_outbound }
    : { status: "ok" }
}

/**
 * Per-service verdict used by the Leak Scanner. Richer than {@link LeakCheckState}:
 * a leaking verdict carries BOTH the expected and the actual outbound so the
 * scanner table and the fix preview can spell out exactly where the service goes
 * vs. where its rule says it should ("goes through {actual}, expected {expected}").
 */
export type ServiceScanState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ok" }
  | { status: "leaking"; expectedOutbound: string; actualOutbound: string }

/**
 * Maps a routing-test response into a Leak Scanner verdict, capturing the
 * expected vs. actual outbound of the first failing IPv4 row. Used instead of
 * {@link evaluateLeakCheck} where the UI needs to show both outbounds (the
 * latter only carries the actual one, and its shape is asserted by tests).
 */
export function evaluateServiceScan(
  diagnostics: RoutingTestResponse
): ServiceScanState {
  const leakRow = findIpv4LeakRow(diagnostics.results)

  return leakRow
    ? {
        status: "leaking",
        expectedOutbound: leakRow.expected_outbound,
        actualOutbound: leakRow.actual_outbound,
      }
    : { status: "ok" }
}

/**
 * Runs a single service scan: like {@link runServiceLeakCheck} but resolves to
 * the richer {@link ServiceScanState} (expected + actual outbound). Never throws;
 * request failures and non-200 responses collapse to an `error` verdict.
 */
export async function runServiceScan(
  target: string,
  runTest: (target: string) => Promise<
    | { status: 200; data: RoutingTestResponse }
    | { status: number; data: unknown }
  >
): Promise<ServiceScanState> {
  try {
    const response = await runTest(target)

    return response.status === 200
      ? evaluateServiceScan(response.data as RoutingTestResponse)
      : { status: "error" }
  } catch {
    return { status: "error" }
  }
}

/** Number of inline domains for a list (0 when none). Used for the scanner's "# affected domains". */
export function getServiceDomainCount(list: ListConfig): number {
  return (list.domains ?? []).filter((domain) => domain.trim().length > 0).length
}

/**
 * Runs the leak check for a single service target. `runTest` performs the
 * actual routing-test request (so both single-row and batch callers share this
 * verdict logic and the same error/200 handling). Never throws: request
 * failures collapse to an `error` verdict.
 */
export async function runServiceLeakCheck(
  target: string,
  runTest: (target: string) => Promise<
    | { status: 200; data: RoutingTestResponse }
    | { status: number; data: unknown }
  >
): Promise<LeakCheckState> {
  try {
    const response = await runTest(target)

    return response.status === 200
      ? evaluateLeakCheck(response.data as RoutingTestResponse)
      : { status: "error" }
  } catch {
    return { status: "error" }
  }
}

/**
 * Collects the inline domains of every service whose latest leak verdict is
 * `leaking`, deduped and sorted, for the auto-heal "fix detected leaks" flow.
 *
 * Only `domains` are promoted (the auto-heal list is domain-based); IP-only
 * services contribute nothing. Services missing from `lists`, services with no
 * inline domains, and non-leaking verdicts are skipped. The result is stable
 * (sorted) so the confirm prompt and request payload read deterministically.
 */
export function collectLeakingDomains(
  leakChecks: Record<string, LeakCheckState | undefined>,
  lists: Record<string, ListConfig>
): string[] {
  const collected = new Set<string>()

  for (const [service, verdict] of Object.entries(leakChecks)) {
    if (verdict?.status !== "leaking") {
      continue
    }

    for (const domain of lists[service]?.domains ?? []) {
      const trimmed = domain.trim()
      if (trimmed.length > 0) {
        collected.add(trimmed)
      }
    }
  }

  return [...collected].sort()
}

/**
 * Runs `worker` over `items` with at most `concurrency` in flight at once, in
 * source order. Each settled item invokes `onResult` so callers can update UI
 * incrementally. `shouldStop` is polled before starting each item, letting a
 * caller cancel an in-progress batch (already-running items still settle, but
 * no new ones are started). Resolves once the queue drains or is cancelled.
 */
export async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
  options?: {
    onResult?: () => void
    shouldStop?: () => boolean
  }
): Promise<void> {
  const limit = Math.max(1, Math.floor(concurrency))
  let cursor = 0

  const runNext = async (): Promise<void> => {
    while (cursor < items.length) {
      if (options?.shouldStop?.()) {
        return
      }

      const item = items[cursor]
      cursor += 1

      await worker(item)
      options?.onResult?.()
    }
  }

  const runners = Array.from({ length: Math.min(limit, items.length) }, () =>
    runNext()
  )

  await Promise.all(runners)
}
