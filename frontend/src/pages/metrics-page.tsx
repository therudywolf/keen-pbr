import type { ReactNode } from "react"
import { useMemo } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { ShieldCheck, Wifi } from "lucide-react"

import type { ApiError } from "@/api/client"
import { apiFetch } from "@/api/client"
import { DataTable } from "@/components/shared/data-table"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { SectionCard } from "@/components/shared/section-card"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Badge } from "@/components/ui/badge"
import {
  ROUTER_RUNTIME_POLL_MS,
  routerFriendlyPollingMs,
} from "@/lib/router-friendly-query"
import { formatBytes, formatCount } from "@/lib/format-bytes"

/** Outbound tags to surface as the VPN-vs-WAN headline. */
const VPN_OUTBOUND_TAG = "forestserver_ru"
const WAN_OUTBOUND_TAG = "rostelecom"

/** Per-outbound traffic counters from `GET /api/metrics/traffic`. */
export interface TrafficMetricsOutbound {
  tag: string
  fwmark: number
  packets: number
  bytes: number
}

/** Response body of `GET /api/metrics/traffic`. */
export interface TrafficMetricsResponse {
  outbounds: TrafficMetricsOutbound[]
  note: string
}

/**
 * Query result: either the endpoint is live with a payload, or it is not
 * available yet (the backend returns 404 until the metrics feature ships).
 */
type TrafficMetricsResult =
  | { available: true; data: TrafficMetricsResponse }
  | { available: false }

const TRAFFIC_METRICS_QUERY_KEY = ["/api/metrics/traffic"] as const

async function fetchTrafficMetrics(
  signal: AbortSignal,
): Promise<TrafficMetricsResult> {
  try {
    const response = await apiFetch<{
      data: TrafficMetricsResponse
      status: number
    }>("/api/metrics/traffic", { method: "GET", signal })

    return { available: true, data: response.data }
  } catch (error) {
    // The endpoint ships in a parallel backend change; until then it 404s.
    // Treat that as a graceful "not available yet" state, not a hard error.
    if ((error as ApiError | undefined)?.status === 404) {
      return { available: false }
    }

    throw error
  }
}

export function MetricsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const pollTrafficMetrics = useMemo(
    () => routerFriendlyPollingMs(queryClient, ROUTER_RUNTIME_POLL_MS),
    [queryClient],
  )

  const metricsQuery = useQuery({
    queryKey: TRAFFIC_METRICS_QUERY_KEY,
    queryFn: ({ signal }) => fetchTrafficMetrics(signal),
    refetchInterval: pollTrafficMetrics,
    refetchIntervalInBackground: false,
    // A 404 is resolved (not thrown); only retry genuine transient failures,
    // and never hammer the router with more than one retry.
    retry: 1,
  })

  const result = metricsQuery.data
  const metrics = result?.available ? result.data : undefined
  const outbounds = useMemo(() => metrics?.outbounds ?? [], [metrics])

  const vpn = useMemo(
    () => outbounds.find((outbound) => outbound.tag === VPN_OUTBOUND_TAG),
    [outbounds],
  )
  const wan = useMemo(
    () => outbounds.find((outbound) => outbound.tag === WAN_OUTBOUND_TAG),
    [outbounds],
  )

  const tableRows = useMemo(
    () =>
      [...outbounds]
        .sort((a, b) => b.bytes - a.bytes)
        .map((outbound) => [
          <span className="font-mono font-medium" key={`${outbound.tag}-tag`}>
            {outbound.tag}
          </span>,
          <span
            className="font-mono tabular-nums"
            key={`${outbound.tag}-bytes`}
          >
            {formatBytes(outbound.bytes)}
          </span>,
          <span
            className="font-mono tabular-nums text-muted-foreground"
            key={`${outbound.tag}-packets`}
          >
            {formatCount(outbound.packets)}
          </span>,
          <span
            className="font-mono text-sm text-muted-foreground"
            key={`${outbound.tag}-fwmark`}
          >
            {formatFwmark(outbound.fwmark)}
          </span>,
        ]),
    [outbounds],
  )

  return (
    <div className="space-y-6">
      <PageHeader
        description={t("pages.metrics.description")}
        title={t("pages.metrics.title")}
      />

      {metricsQuery.isLoading ? (
        <TableSkeleton />
      ) : metricsQuery.isError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : !metrics ? (
        <ListPlaceholder
          description={t("pages.metrics.unavailable.description")}
          title={t("pages.metrics.unavailable.title")}
        />
      ) : outbounds.length === 0 ? (
        <ListPlaceholder
          description={t("pages.metrics.empty.description")}
          title={t("pages.metrics.empty.title")}
        />
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <HeadlineCard
              icon={<ShieldCheck className="h-4 w-4 text-success" />}
              subtitle={t("pages.metrics.headline.vpnSubtitle", {
                tag: VPN_OUTBOUND_TAG,
              })}
              terminalFilename="metrics.vpn"
              title={t("pages.metrics.headline.vpn")}
              tone="vpn"
              outbound={vpn}
              t={t}
            />
            <HeadlineCard
              icon={<Wifi className="h-4 w-4 text-warning-foreground" />}
              subtitle={t("pages.metrics.headline.wanSubtitle", {
                tag: WAN_OUTBOUND_TAG,
              })}
              terminalFilename="metrics.wan"
              title={t("pages.metrics.headline.wan")}
              tone="wan"
              outbound={wan}
              t={t}
            />
          </div>

          <SectionCard
            terminalFilename="metrics.outbounds"
            title={t("pages.metrics.table.title")}
          >
            <DataTable
              headers={[
                t("pages.metrics.headers.tag"),
                t("pages.metrics.headers.bytes"),
                t("pages.metrics.headers.packets"),
                t("pages.metrics.headers.fwmark"),
              ]}
              narrowColumns={[1, 2]}
              rows={tableRows}
            />
            {metrics.note ? (
              <p className="mt-3 text-xs text-muted-foreground">
                {metrics.note}
              </p>
            ) : null}
          </SectionCard>
        </div>
      )}
    </div>
  )
}

type TranslateFn = (key: string, options?: Record<string, unknown>) => string

function HeadlineCard({
  title,
  subtitle,
  icon,
  tone,
  outbound,
  terminalFilename,
  t,
}: {
  title: string
  subtitle: string
  icon: ReactNode
  tone: "vpn" | "wan"
  outbound: TrafficMetricsOutbound | undefined
  terminalFilename: string
  t: TranslateFn
}) {
  return (
    <SectionCard terminalFilename={terminalFilename} title={title}>
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          {icon}
          <Badge size="xs" variant={tone === "vpn" ? "success" : "warning"}>
            <span className="font-mono">{subtitle}</span>
          </Badge>
        </div>
        {outbound ? (
          <div className="space-y-1">
            <div className="font-mono text-3xl font-semibold tabular-nums tracking-tight">
              {formatBytes(outbound.bytes)}
            </div>
            <div className="font-mono text-sm text-muted-foreground">
              {t("pages.metrics.headline.packets", {
                count: formatCount(outbound.packets),
              })}
            </div>
          </div>
        ) : (
          <div className="font-mono text-sm text-muted-foreground">
            {t("pages.metrics.headline.noData")}
          </div>
        )}
      </div>
    </SectionCard>
  )
}

/** Renders an fwmark as hex (matches how routing rules display marks). */
function formatFwmark(fwmark: number): string {
  if (!Number.isFinite(fwmark)) {
    return "-"
  }

  return `0x${(fwmark >>> 0).toString(16)}`
}
