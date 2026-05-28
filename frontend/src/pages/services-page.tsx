import { Loader2, Search, ShieldAlert, ShieldCheck } from "lucide-react"
import { useMemo, useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type {
  RoutingTestResponse,
  RuntimeOutboundState,
} from "@/api/generated/model"
import type { ListConfig } from "@/api/generated/model/listConfig"
import {
  usePostConfigMutation,
  usePostRoutingTestMutation,
  useConfigMutationPending,
} from "@/api/mutations"
import { useGetConfig, useGetRuntimeOutbounds } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { DataTable } from "@/components/shared/data-table"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { OutboundSelect } from "@/components/shared/outbound-select"
import { PageHeader } from "@/components/shared/page-header"
import { RuntimeOutboundEntry, RuntimeOutboundStatusLabel } from "@/components/shared/runtime-outbound-state"
import { SectionCard } from "@/components/shared/section-card"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  ROUTER_RUNTIME_POLL_MS,
  routerFriendlyPollingMs,
} from "@/lib/router-friendly-query"
import {
  findIpv4LeakRow,
  getServiceEntryCount,
  getServiceLeakCheckTarget,
  getServiceOutbound,
  reassignServiceOutbound,
} from "@/pages/services-utils"

/** Outbound tags worth highlighting in the health summary. */
const VPN_OUTBOUND_TAG = "forestserver_ru"
const WAN_OUTBOUND_TAG = "rostelecom"

type LeakCheckState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ok" }
  | { status: "leaking"; actualOutbound: string }

export function ServicesPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const configMutationPending = useConfigMutationPending()

  const pollRuntimeOutbounds = useMemo(
    () => routerFriendlyPollingMs(queryClient, ROUTER_RUNTIME_POLL_MS),
    [queryClient],
  )

  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const routeRules = useMemo(
    () => loadedConfig?.route?.rules ?? [],
    [loadedConfig?.route?.rules],
  )
  const outbounds = useMemo(
    () => loadedConfig?.outbounds ?? [],
    [loadedConfig?.outbounds],
  )

  const runtimeOutboundsQuery = useGetRuntimeOutbounds({
    query: {
      refetchInterval: pollRuntimeOutbounds,
      refetchIntervalInBackground: false,
    },
  })
  const runtimeOutbounds = useMemo(
    () =>
      runtimeOutboundsQuery.data?.status === 200
        ? runtimeOutboundsQuery.data.data.outbounds
        : [],
    [runtimeOutboundsQuery.data],
  )
  const runtimeOutboundByTag = useMemo(
    () =>
      new Map(
        runtimeOutbounds.map((runtimeOutbound) => [
          runtimeOutbound.tag,
          runtimeOutbound,
        ]),
      ),
    [runtimeOutbounds],
  )

  const [searchQuery, setSearchQuery] = useState("")
  const [leakChecks, setLeakChecks] = useState<Record<string, LeakCheckState>>(
    {},
  )

  const services = useMemo(
    () => Object.entries(loadedConfig?.lists ?? {}),
    [loadedConfig?.lists],
  )
  const normalizedQuery = searchQuery.trim().toLowerCase()
  const filteredServices = useMemo(
    () =>
      normalizedQuery
        ? services.filter(([name]) =>
            name.toLowerCase().includes(normalizedQuery),
          )
        : services,
    [services, normalizedQuery],
  )

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: () => {
        toast.success(t("pages.services.messages.saved"))
      },
      onError: (error) => {
        toast.error(getApiErrorMessage(error as ApiError), { richColors: true })
      },
    },
  })

  const routingTestMutation = usePostRoutingTestMutation()

  const handleOutboundChange = (service: string, targetOutbound: string) => {
    if (!loadedConfig || !targetOutbound) {
      return
    }

    const nextRules = reassignServiceOutbound(routeRules, service, targetOutbound)
    postConfigMutation.mutate({
      data: {
        ...loadedConfig,
        route: {
          ...loadedConfig.route,
          rules: nextRules,
        },
      },
    })
  }

  const handleLeakCheck = (service: string, list: ListConfig) => {
    const target = getServiceLeakCheckTarget(list)
    if (!target) {
      toast.warning(t("pages.services.messages.noTestableEntry"), {
        richColors: true,
      })
      return
    }

    setLeakChecks((previous) => ({
      ...previous,
      [service]: { status: "loading" },
    }))

    routingTestMutation.mutate(
      { data: { target } },
      {
        onSuccess: (response) => {
          setLeakChecks((previous) => ({
            ...previous,
            [service]:
              response.status === 200
                ? evaluateLeakCheck(response.data)
                : { status: "error" },
          }))
        },
        onError: () => {
          setLeakChecks((previous) => ({
            ...previous,
            [service]: { status: "error" },
          }))
        },
      },
    )
  }

  const tableRows = filteredServices.map(([service, list]) => {
    const entryCount = getServiceEntryCount(list)
    const currentOutbound = getServiceOutbound(routeRules, service)

    return [
      <span className="font-mono font-medium" key={`${service}-name`}>
        {service}
      </span>,
      <span
        className="font-mono text-sm text-muted-foreground"
        key={`${service}-entries`}
      >
        {entryCount ?? t("common.noneShort")}
      </span>,
      <div key={`${service}-current`}>
        {currentOutbound ? (
          <RuntimeOutboundEntry
            runtimeState={runtimeOutboundByTag.get(currentOutbound)}
            title={currentOutbound}
            t={t}
          />
        ) : (
          <span className="text-sm text-muted-foreground">
            {t("common.noneShort")}
          </span>
        )}
      </div>,
      <div className="min-w-[14rem]" key={`${service}-change`}>
        <OutboundSelect
          disabled={configMutationPending}
          onValueChange={(value) => handleOutboundChange(service, value)}
          outbounds={outbounds}
          placeholder={t("pages.services.actions.selectOutbound")}
          value={currentOutbound ?? ""}
        />
      </div>,
      <LeakCheckCell
        key={`${service}-leak`}
        onCheck={() => handleLeakCheck(service, list)}
        pending={
          routingTestMutation.isPending &&
          leakChecks[service]?.status === "loading"
        }
        state={leakChecks[service]}
      />,
    ]
  })

  return (
    <div className="space-y-6">
      <PageHeader
        description={t("pages.services.description")}
        title={t("pages.services.title")}
      />

      <OutboundHealthSummary
        runtimeOutbounds={runtimeOutbounds}
        t={t}
      />

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {configQuery.isLoading ? (
        <TableSkeleton />
      ) : configQuery.isError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : services.length === 0 ? (
        <ListPlaceholder
          description={t("pages.services.empty.description")}
          title={t("pages.services.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          <div className="relative max-w-sm">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label={t("pages.services.searchPlaceholder")}
              className="pl-8"
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder={t("pages.services.searchPlaceholder")}
              value={searchQuery}
            />
          </div>

          {tableRows.length === 0 ? (
            <ListPlaceholder
              description={t("pages.services.noMatches.description")}
              title={t("pages.services.noMatches.title")}
            />
          ) : (
            <DataTable
              headers={[
                t("pages.services.headers.service"),
                t("pages.services.headers.entries"),
                t("pages.services.headers.currentOutbound"),
                t("pages.services.headers.change"),
                t("pages.services.headers.leakCheck"),
              ]}
              narrowColumns={[1]}
              rows={tableRows}
            />
          )}
        </div>
      )}
    </div>
  )
}

type TranslateFn = (key: string, options?: Record<string, unknown>) => string

function OutboundHealthSummary({
  runtimeOutbounds,
  t,
}: {
  runtimeOutbounds: RuntimeOutboundState[]
  t: TranslateFn
}) {
  if (runtimeOutbounds.length === 0) {
    return null
  }

  const sorted = [...runtimeOutbounds].sort(
    (a, b) => highlightRank(a.tag) - highlightRank(b.tag),
  )

  return (
    <SectionCard
      terminalFilename="outbounds.health"
      title={t("pages.services.health.title")}
    >
      <div className="flex flex-wrap gap-2">
        {sorted.map((runtimeOutbound) => (
          <div
            className="rounded-lg border bg-muted/30 px-3 py-2"
            key={runtimeOutbound.tag}
          >
            <RuntimeOutboundStatusLabel
              runtimeState={runtimeOutbound}
              t={t}
              title={highlightLabel(runtimeOutbound.tag, t)}
            />
          </div>
        ))}
      </div>
    </SectionCard>
  )
}

function highlightRank(tag: string): number {
  if (tag === VPN_OUTBOUND_TAG) {
    return 0
  }
  if (tag === WAN_OUTBOUND_TAG) {
    return 1
  }

  return 2
}

function highlightLabel(tag: string, t: TranslateFn): string {
  if (tag === VPN_OUTBOUND_TAG) {
    return t("pages.services.health.vpn", { tag })
  }
  if (tag === WAN_OUTBOUND_TAG) {
    return t("pages.services.health.wan", { tag })
  }

  return tag
}

function LeakCheckCell({
  state,
  pending,
  onCheck,
}: {
  state: LeakCheckState | undefined
  pending: boolean
  onCheck: () => void
}) {
  const { t } = useTranslation()

  return (
    <div className="flex items-center justify-end gap-2">
      {state?.status === "ok" ? (
        <Badge size="xs" variant="success">
          <ShieldCheck className="h-3 w-3" />
          {t("pages.services.leak.ok")}
        </Badge>
      ) : null}
      {state?.status === "leaking" ? (
        <Badge size="xs" variant="destructive">
          <ShieldAlert className="h-3 w-3" />
          {t("pages.services.leak.leaking", {
            outbound: state.actualOutbound,
          })}
        </Badge>
      ) : null}
      {state?.status === "error" ? (
        <span className="text-xs text-destructive">
          {t("pages.services.leak.failed")}
        </span>
      ) : null}
      <Button
        disabled={pending}
        onClick={onCheck}
        size="sm"
        variant="outline"
      >
        {pending ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
        {t("pages.services.actions.check")}
      </Button>
    </div>
  )
}

/** Maps a routing-test response into a leak verdict for the service row. */
function evaluateLeakCheck(diagnostics: RoutingTestResponse): LeakCheckState {
  const leakRow = findIpv4LeakRow(diagnostics.results)

  return leakRow
    ? { status: "leaking", actualOutbound: leakRow.actual_outbound }
    : { status: "ok" }
}
