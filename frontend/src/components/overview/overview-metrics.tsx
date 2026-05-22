import { useTranslation } from "react-i18next"

import type {
  ConfigObject,
  RoutingHealthResponse,
  RuntimeInterfaceInventoryEntry,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { RuntimeInterfaceInventoryStatus } from "@/api/generated/model/runtimeInterfaceInventoryStatus"
import { MetricCard, type MetricTone } from "@/components/overview/metric-card"
import { SectionCard } from "@/components/shared/section-card"
import { Skeleton } from "@/components/ui/skeleton"

/**
 * The Reference-A metric grid for the dashboard: a row of metric cards built
 * from config + runtime data. Every number here is derived from data the page
 * already fetches, so this panel adds no extra requests.
 */
export function OverviewMetrics({
  config,
  runtimeOutbounds,
  runtimeInterfaces,
  routingHealth,
  isLoading,
}: {
  config?: ConfigObject
  runtimeOutbounds: RuntimeOutboundState[]
  runtimeInterfaces: RuntimeInterfaceInventoryEntry[]
  routingHealth?: RoutingHealthResponse
  isLoading: boolean
}) {
  const { t } = useTranslation()

  const outboundsTotal = config?.outbounds?.length ?? 0
  const outboundsReachable = runtimeOutbounds.filter(
    (outbound) => outbound.status === "healthy",
  ).length
  const outboundsDegraded = runtimeOutbounds.filter(
    (outbound) =>
      outbound.status === "degraded" || outbound.status === "unavailable",
  ).length

  const routingRulesCount = config?.route?.rules?.length ?? 0
  const dnsRulesCount = config?.dns?.rules?.length ?? 0
  const dnsServersCount = config?.dns?.servers?.length ?? 0

  const lists = config?.lists ?? {}
  const listsCount = Object.keys(lists).length
  const listEntriesTotal = Object.values(lists).reduce(
    (sum, list) =>
      sum + (list.domains?.length ?? 0) + (list.ip_cidrs?.length ?? 0),
    0,
  )

  const interfacesUp = runtimeInterfaces.filter(
    (entry) => entry.status === RuntimeInterfaceInventoryStatus.up,
  ).length
  const interfacesTotal = runtimeInterfaces.length

  // Reachability tone: green when all known outbounds are healthy, amber for
  // partial availability, crimson when nothing is reachable but some exist.
  const reachabilityTone: MetricTone =
    runtimeOutbounds.length === 0
      ? "neutral"
      : outboundsReachable === runtimeOutbounds.length
        ? "healthy"
        : outboundsReachable === 0
          ? "critical"
          : "warning"

  if (isLoading) {
    return (
      <SectionCard
        terminalFilename="metrics.stat"
        title={t("overview.metrics.title")}
      >
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton className="h-[5.25rem] w-full rounded-lg" key={index} />
          ))}
        </div>
      </SectionCard>
    )
  }

  return (
    <SectionCard
      description={t("overview.metrics.description")}
      terminalFilename="metrics.stat"
      title={t("overview.metrics.title")}
    >
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
        <MetricCard
          fill={
            runtimeOutbounds.length > 0
              ? outboundsReachable / runtimeOutbounds.length
              : outboundsTotal > 0
                ? 1
                : 0
          }
          hint={t("overview.metrics.outboundsConfigured", {
            count: outboundsTotal,
          })}
          label={t("overview.metrics.outboundsReachable")}
          tone={reachabilityTone}
          unit={
            runtimeOutbounds.length > 0
              ? t("overview.metrics.ofTotal", {
                  total: runtimeOutbounds.length,
                })
              : undefined
          }
          value={
            runtimeOutbounds.length > 0 ? outboundsReachable : outboundsTotal
          }
        />
        <MetricCard
          fill={runtimeOutbounds.length > 0 ? outboundsDegraded / runtimeOutbounds.length : 0}
          label={t("overview.metrics.outboundsDegraded")}
          tone={outboundsDegraded > 0 ? "warning" : "healthy"}
          value={outboundsDegraded}
        />
        <MetricCard
          label={t("overview.metrics.routingRules")}
          tone={routingRulesCount > 0 ? "info" : "neutral"}
          value={routingRulesCount}
        />
        <MetricCard
          label={t("overview.metrics.dnsRules")}
          tone={dnsRulesCount > 0 ? "info" : "neutral"}
          value={dnsRulesCount}
        />
        <MetricCard
          hint={t("overview.metrics.listEntries", {
            count: listEntriesTotal,
          })}
          label={t("overview.metrics.lists")}
          tone={listsCount > 0 ? "info" : "neutral"}
          value={listsCount}
        />
        <MetricCard
          label={t("overview.metrics.dnsServers")}
          tone={dnsServersCount > 0 ? "info" : "neutral"}
          value={dnsServersCount}
        />
        <MetricCard
          fill={interfacesTotal > 0 ? interfacesUp / interfacesTotal : 0}
          label={t("overview.metrics.interfacesUp")}
          tone={
            interfacesTotal === 0
              ? "neutral"
              : interfacesUp > 0
                ? "healthy"
                : "critical"
          }
          unit={
            interfacesTotal > 0
              ? t("overview.metrics.ofTotal", { total: interfacesTotal })
              : undefined
          }
          value={interfacesUp}
        />
        {routingHealth ? (
          <MetricCard
            label={t("overview.metrics.firewallBackend")}
            tone="info"
            value={
              <span className="text-base">
                {routingHealth.firewall_backend}
              </span>
            }
          />
        ) : null}
      </div>
    </SectionCard>
  )
}
