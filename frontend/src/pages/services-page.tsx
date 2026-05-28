import { Loader2, Search, ShieldAlert, ShieldCheck, Sparkles, X } from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import { apiFetch } from "@/api/client"
import type { RuntimeOutboundState } from "@/api/generated/model"
import type { ListConfig } from "@/api/generated/model/listConfig"
import {
  postRoutingTest,
  usePostConfigMutation,
  usePostRoutingTestMutation,
  useConfigMutationPending,
} from "@/api/mutations"
import { useGetConfig, useGetRuntimeOutbounds } from "@/api/queries"
import { invalidationKeysAfterConfigMutation } from "@/api/query-keys"
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
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  ROUTER_RUNTIME_POLL_MS,
  routerFriendlyPollingMs,
} from "@/lib/router-friendly-query"
import {
  collectLeakingDomains,
  getServiceEntryCount,
  getServiceLeakCheckTarget,
  getServiceOutbound,
  reassignServiceOutbound,
  runServiceLeakCheck,
  runWithConcurrency,
  type LeakCheckState,
} from "@/pages/services-utils"

/** Outbound tags worth highlighting in the health summary. */
const VPN_OUTBOUND_TAG = "forestserver_ru"
const WAN_OUTBOUND_TAG = "rostelecom"

/** Max concurrent leak checks during a "Check all" run (keep low for weak routers). */
const BATCH_LEAK_CHECK_CONCURRENCY = 3

type BatchProgress = {
  done: number
  total: number
}

/** Response body of `POST /api/autoheal/promote`. */
interface AutohealPromoteResponse {
  added: string[]
  list: string
  staged: true
}

/**
 * Stages the given domains into the auto-heal list (a config draft, committed
 * later by the global Apply banner). Returns the parsed body. The endpoint
 * ships with a parallel backend change; until then it 404s and the mutation's
 * onError surfaces a friendly message rather than crashing the page.
 */
async function postAutohealPromote(
  domains: string[],
): Promise<AutohealPromoteResponse> {
  const response = await apiFetch<{
    data: AutohealPromoteResponse
    status: number
  }>("/api/autoheal/promote", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains }),
  })

  return response.data
}

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
  const [batchProgress, setBatchProgress] = useState<BatchProgress | null>(null)
  // Set true to ask an in-flight "Check all" run to stop launching new checks.
  const batchCancelledRef = useRef(false)
  // Gate the "Auto-fix leaks" button so it only appears after a finished
  // "Check all" run (a single-row check shouldn't surface a bulk fix action).
  const [checkAllCompleted, setCheckAllCompleted] = useState(false)

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

  // Domains of every service whose latest verdict is "leaking", deduped + sorted.
  const leakingDomains = useMemo(
    () => collectLeakingDomains(leakChecks, loadedConfig?.lists ?? {}),
    [leakChecks, loadedConfig?.lists],
  )

  const autohealPromoteMutation = useMutation<
    AutohealPromoteResponse,
    ApiError,
    string[]
  >({
    mutationKey: ["autohealPromote"],
    mutationFn: (domains: string[]) => postAutohealPromote(domains),
    onSuccess: async (data) => {
      // Staging a config draft — refresh config state so the global Apply banner
      // shows, exactly like other config mutations on this page.
      for (const queryKey of invalidationKeysAfterConfigMutation) {
        await queryClient.invalidateQueries({ queryKey })
      }
      toast.success(
        t("pages.services.autofix.success", { count: data.added.length }),
        { richColors: true },
      )
    },
    onError: (error) => {
      toast.error(getApiErrorMessage(error), { richColors: true })
    },
  })

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

  /**
   * Shared leak-check runner used by both the single-row button and the batch
   * "Check all" flow: mark the row loading, probe the service's target via
   * `runTest`, then store the verdict. `runTest` defaults to the per-row
   * mutation; the batch passes the raw request so its checks stay independent
   * of the single mutation's shared pending flag.
   */
  const runLeakCheckForService = useCallback(
    async (
      service: string,
      list: ListConfig,
      runTest: (target: string) => Promise<
        Awaited<ReturnType<typeof postRoutingTest>>
      > = (target) => routingTestMutation.mutateAsync({ data: { target } }),
    ): Promise<LeakCheckState | undefined> => {
      const target = getServiceLeakCheckTarget(list)
      if (!target) {
        return undefined
      }

      setLeakChecks((previous) => ({
        ...previous,
        [service]: { status: "loading" },
      }))

      const verdict = await runServiceLeakCheck(target, runTest)

      setLeakChecks((previous) => ({
        ...previous,
        [service]: verdict,
      }))

      return verdict
    },
    [routingTestMutation],
  )

  const handleLeakCheck = useCallback(
    (service: string, list: ListConfig) => {
      const target = getServiceLeakCheckTarget(list)
      if (!target) {
        toast.warning(t("pages.services.messages.noTestableEntry"), {
          richColors: true,
        })
        return
      }

      void runLeakCheckForService(service, list)
    },
    [runLeakCheckForService, t],
  )

  const isBatchRunning = batchProgress !== null

  const handleCheckAll = useCallback(async () => {
    if (isBatchRunning) {
      return
    }

    // Only check services that actually have a testable entry.
    const testable = filteredServices.filter(([, list]) =>
      Boolean(getServiceLeakCheckTarget(list)),
    )
    if (testable.length === 0) {
      toast.warning(t("pages.services.messages.noTestableEntry"), {
        richColors: true,
      })
      return
    }

    batchCancelledRef.current = false
    // Hide the auto-fix button until this fresh run finishes with results.
    setCheckAllCompleted(false)
    setBatchProgress({ done: 0, total: testable.length })

    // Tally verdicts as they settle so the summary is a pure post-run effect
    // (no side effects inside React state updaters, which can run twice).
    let checkedCount = 0
    let leakingCount = 0

    await runWithConcurrency(
      testable,
      BATCH_LEAK_CHECK_CONCURRENCY,
      async ([service, list]) => {
        const verdict = await runLeakCheckForService(
          service,
          list,
          (target) => postRoutingTest({ target }),
        )

        if (verdict) {
          checkedCount += 1
          if (verdict.status === "leaking") {
            leakingCount += 1
          }
        }
      },
      {
        onResult: () =>
          setBatchProgress((previous) =>
            previous ? { ...previous, done: previous.done + 1 } : previous,
          ),
        shouldStop: () => batchCancelledRef.current,
      },
    )

    setBatchProgress(null)

    if (batchCancelledRef.current || checkedCount === 0) {
      return
    }

    // A full run finished with results: allow the auto-fix button to appear if
    // anything is leaking.
    setCheckAllCompleted(true)

    if (leakingCount > 0) {
      toast.warning(
        t("pages.services.batch.summaryLeaking", { count: leakingCount }),
        { richColors: true },
      )
    } else {
      toast.success(t("pages.services.batch.summaryClean"), {
        richColors: true,
      })
    }
  }, [filteredServices, isBatchRunning, runLeakCheckForService, t])

  const handleAutofixLeaks = useCallback(() => {
    if (autohealPromoteMutation.isPending || leakingDomains.length === 0) {
      return
    }

    const confirmed = window.confirm(
      t("pages.services.autofix.confirm", { count: leakingDomains.length }),
    )
    if (!confirmed) {
      return
    }

    autohealPromoteMutation.mutate(leakingDomains)
  }, [autohealPromoteMutation, leakingDomains, t])

  const handleCancelBatch = useCallback(() => {
    batchCancelledRef.current = true
  }, [])

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
        disabled={isBatchRunning}
        onCheck={() => handleLeakCheck(service, list)}
        pending={leakChecks[service]?.status === "loading"}
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
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative w-full sm:max-w-sm">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                aria-label={t("pages.services.searchPlaceholder")}
                className="pl-8"
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder={t("pages.services.searchPlaceholder")}
                value={searchQuery}
              />
            </div>

            <div className="flex items-center gap-2 sm:shrink-0">
              {!isBatchRunning &&
              checkAllCompleted &&
              leakingDomains.length > 0 ? (
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <Button
                        aria-label={t("pages.services.autofix.button", {
                          count: leakingDomains.length,
                        })}
                        disabled={autohealPromoteMutation.isPending}
                        onClick={handleAutofixLeaks}
                        size="sm"
                        variant="default"
                      />
                    }
                  >
                    {autohealPromoteMutation.isPending ? (
                      <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                    ) : (
                      <Sparkles className="mr-1 h-4 w-4" />
                    )}
                    {t("pages.services.autofix.button", {
                      count: leakingDomains.length,
                    })}
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-left">
                    {t("pages.services.autofix.sharedIpNote")}
                  </TooltipContent>
                </Tooltip>
              ) : null}

              {isBatchRunning ? (
                <>
                  <span
                    aria-live="polite"
                    className="font-mono text-xs text-muted-foreground"
                  >
                    {t("pages.services.batch.progress", {
                      done: batchProgress.done,
                      total: batchProgress.total,
                    })}
                  </span>
                  <Button
                    onClick={handleCancelBatch}
                    size="sm"
                    variant="outline"
                  >
                    <X className="mr-1 h-4 w-4" />
                    {t("common.cancel")}
                  </Button>
                </>
              ) : (
                <Button
                  disabled={tableRows.length === 0}
                  onClick={() => void handleCheckAll()}
                  size="sm"
                  variant="outline"
                >
                  <ShieldCheck className="mr-1 h-4 w-4" />
                  {t("pages.services.batch.checkAll")}
                </Button>
              )}
            </div>
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
  disabled,
  onCheck,
}: {
  state: LeakCheckState | undefined
  pending: boolean
  disabled: boolean
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
        disabled={pending || disabled}
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
