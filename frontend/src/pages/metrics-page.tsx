import type { ReactNode } from "react"
import { useMemo } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { ShieldCheck, Sparkles, Wifi } from "lucide-react"

import type { ApiError } from "@/api/client"
import { apiFetch } from "@/api/client"
import { DataTable } from "@/components/shared/data-table"
import { ListChips } from "@/components/shared/list-chips"
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

/** Per-rule-group traffic counters from `GET /api/metrics/traffic`. */
export interface TrafficMetricsRule {
  /** First element of rule_indices, or -1 when unattributable. */
  index: number
  /** Every route.rules index this entry's counters cover (may be empty). */
  rule_indices?: number[]
  outbound: string
  lists: string[]
  /** Kernel set names that contributed counters. */
  sets?: string[]
  packets: number
  bytes: number
}

/** Response body of `GET /api/metrics/traffic`. */
export interface TrafficMetricsResponse {
  outbounds: TrafficMetricsOutbound[]
  /** Optional in older builds; absent/empty -> the per-rule section is hidden. */
  rules?: TrafficMetricsRule[]
  note: string
}

/** Response body of `GET /api/autoheal`. */
export interface AutohealResponse {
  enabled: boolean
  list: string
  outbound: string
  domains: string[]
}

/**
 * Query result: either the endpoint is live with a payload, or it is not
 * available yet (the backend returns 404 until the metrics feature ships).
 */
type TrafficMetricsResult =
  | { available: true; data: TrafficMetricsResponse }
  | { available: false }

type AutohealResult =
  | { available: true; data: AutohealResponse }
  | { available: false }

const TRAFFIC_METRICS_QUERY_KEY = ["/api/metrics/traffic"] as const
const AUTOHEAL_QUERY_KEY = ["/api/autoheal"] as const

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

async function fetchAutoheal(signal: AbortSignal): Promise<AutohealResult> {
  try {
    const response = await apiFetch<{ data: AutohealResponse; status: number }>(
      "/api/autoheal",
      { method: "GET", signal },
    )

    return { available: true, data: response.data }
  } catch (error) {
    // Ships with the parallel backend change; until then it 404s. Same graceful
    // "not available yet" handling as the traffic metrics query above.
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

  const autohealQuery = useQuery({
    queryKey: AUTOHEAL_QUERY_KEY,
    queryFn: ({ signal }) => fetchAutoheal(signal),
    refetchInterval: pollTrafficMetrics,
    refetchIntervalInBackground: false,
    retry: 1,
  })

  const result = metricsQuery.data
  const metrics = result?.available ? result.data : undefined
  const outbounds = useMemo(() => metrics?.outbounds ?? [], [metrics])
  const rules = useMemo(() => metrics?.rules ?? [], [metrics])

  const autohealResult = autohealQuery.data
  const autoheal = autohealResult?.available ? autohealResult.data : undefined

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

  const ruleRows = useMemo(
    () =>
      [...rules]
        .sort((a, b) => b.bytes - a.bytes)
        .map((rule) => [
          <span
            className="font-mono font-medium tabular-nums"
            key={`rule-${rule.index}-index`}
          >
            {(rule.rule_indices?.length ?? 0) > 0
              ? rule.rule_indices!.map((i) => `#${i}`).join("+")
              : rule.index >= 0
                ? `#${rule.index}`
                : "—"}
          </span>,
          <span className="font-mono" key={`rule-${rule.index}-outbound`}>
            {rule.outbound}
          </span>,
          <ListChips
            inlineLimit={3}
            key={`rule-${rule.index}-lists`}
            lists={rule.lists ?? []}
          />,
          <span
            className="font-mono tabular-nums"
            key={`rule-${rule.index}-bytes`}
          >
            {formatBytes(rule.bytes)}
          </span>,
          <span
            className="font-mono tabular-nums text-muted-foreground"
            key={`rule-${rule.index}-packets`}
          >
            {formatCount(rule.packets)}
          </span>,
        ]),
    [rules],
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

          {ruleRows.length > 0 ? (
            <SectionCard
              terminalFilename="metrics.rules"
              title={t("pages.metrics.rules.title")}
            >
              <DataTable
                headers={[
                  t("pages.metrics.rules.headers.rule"),
                  t("pages.metrics.rules.headers.outbound"),
                  t("pages.metrics.rules.headers.lists"),
                  t("pages.metrics.rules.headers.bytes"),
                  t("pages.metrics.rules.headers.packets"),
                ]}
                narrowColumns={[0, 3]}
                rows={ruleRows}
              />
            </SectionCard>
          ) : null}
        </div>
      )}

      <AutohealCard
        autoheal={autoheal}
        isError={autohealQuery.isError}
        isLoading={autohealQuery.isLoading}
        t={t}
      />
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

/**
 * Read-only auto-heal ("самолечение") status panel at the bottom of the page:
 * shows whether self-healing is enabled, the auto list name + its outbound, and
 * the currently auto-promoted domains. While the backend endpoint is undeployed
 * it 404s (resolved to `autoheal === undefined` upstream) or errors transiently;
 * in both cases the whole section is omitted rather than showing an error, so an
 * older build's Metrics page is unchanged.
 */
function AutohealCard({
  autoheal,
  isLoading,
  isError,
  t,
}: {
  autoheal: AutohealResponse | undefined
  isLoading: boolean
  isError: boolean
  t: TranslateFn
}) {
  if (isLoading || isError || !autoheal) {
    return null
  }

  const domains = autoheal.domains ?? []

  return (
    <SectionCard
      terminalFilename="metrics.autoheal"
      title={t("pages.metrics.autoheal.title")}
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          <Badge size="xs" variant={autoheal.enabled ? "success" : "secondary"}>
            {autoheal.enabled
              ? t("pages.metrics.autoheal.enabled")
              : t("pages.metrics.autoheal.disabled")}
          </Badge>
          {autoheal.list ? (
            <span className="font-mono text-xs text-muted-foreground">
              {t("pages.metrics.autoheal.target", {
                list: autoheal.list,
                outbound: autoheal.outbound,
              })}
            </span>
          ) : null}
        </div>

        <div className="space-y-1.5">
          <div className="font-mono text-[11px] text-muted-foreground">
            {t("pages.metrics.autoheal.domainsCount", {
              count: domains.length,
            })}
          </div>
          {domains.length > 0 ? (
            <ListChips inlineLimit={12} lists={domains} />
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("pages.metrics.autoheal.empty")}
            </p>
          )}
        </div>
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
