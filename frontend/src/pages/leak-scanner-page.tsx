import {
  ArrowRight,
  Loader2,
  RadarIcon,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from "lucide-react"
import { useCallback, useMemo, useRef, useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type { ListConfig } from "@/api/generated/model/listConfig"
import type { RouteRule } from "@/api/generated/model/routeRule"
import {
  postRoutingTest,
  usePostConfigMutation,
  useConfigMutationPending,
} from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { queryKeys } from "@/api/query-keys"
import { selectConfig } from "@/api/selectors"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { DataTable, type DataTableSelection } from "@/components/shared/data-table"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { SectionCard } from "@/components/shared/section-card"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  getServiceDomainCount,
  getServiceLeakCheckTarget,
  getServiceOutbound,
  reassignServiceOutbound,
  runServiceScan,
  runWithConcurrency,
  type ServiceScanState,
} from "@/pages/services-utils"

/** Max concurrent scans in flight at once (kept low to stay gentle on weak routers). */
const SCAN_CONCURRENCY = 3

type ScanProgress = {
  done: number
  total: number
}

/** A service whose latest scan verdict is "leaking" — the unit of the results table and the fix. */
type LeakRow = {
  service: string
  /** Where the service should go, for display ("expected {expected}"). */
  expectedOutbound: string
  /** Where the service currently goes (live kernel state). */
  actualOutbound: string
  /**
   * The real, configured outbound tag to move the service back to. Resolved from
   * the service's own route rule (falling back to the scan's expected when that
   * is a real tag, not a "(default)"/"(unknown)" placeholder). undefined when the
   * service has no fixable target — those rows are shown but not fixable.
   */
  fixTarget?: string
  domainCount: number
}

export function LeakScannerPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const configMutationPending = useConfigMutationPending()

  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const routeRules = useMemo(
    () => loadedConfig?.route?.rules ?? [],
    [loadedConfig?.route?.rules],
  )
  const lists = useMemo(
    () => loadedConfig?.lists ?? {},
    [loadedConfig?.lists],
  )
  const services = useMemo(() => Object.entries(lists), [lists])
  // Set of real, configured outbound tags — used to reject "(default)"/"(unknown)"
  // placeholders so a fix never targets a non-existent outbound.
  const outboundTags = useMemo(
    () => new Set((loadedConfig?.outbounds ?? []).map((outbound) => outbound.tag)),
    [loadedConfig?.outbounds],
  )

  // Per-service scan verdicts. Only "leaking" entries surface as table rows.
  const [scanResults, setScanResults] = useState<
    Record<string, ServiceScanState>
  >({})
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null)
  // Set true to ask an in-flight scan to stop launching new checks.
  const scanCancelledRef = useRef(false)
  // True once a full scan finished with results — gates the "all clean" message
  // so it never shows before the user has actually scanned.
  const [scanCompleted, setScanCompleted] = useState(false)
  const [selectedServices, setSelectedServices] = useState<Set<string>>(
    () => new Set(),
  )
  // Services queued for the preview/confirm dialog; null = dialog closed.
  const [fixRequest, setFixRequest] = useState<string[] | null>(null)

  const isScanning = scanProgress !== null

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: queryKeys.config() })
      },
      onError: (error) => {
        toast.error(getApiErrorMessage(error as ApiError), { richColors: true })
      },
    },
  })

  // The leaking services, as table rows. Stable order (config order) so the
  // table, the selection and the preview all read deterministically.
  const leakRows = useMemo<LeakRow[]>(() => {
    const rows: LeakRow[] = []
    for (const [service, list] of services) {
      const verdict = scanResults[service]
      if (verdict?.status === "leaking") {
        // Prefer the service's own configured outbound; fall back to the scan's
        // expected only when it is a real tag (never a placeholder).
        const configuredOutbound = getServiceOutbound(routeRules, service)
        const fixTarget =
          configuredOutbound ??
          (outboundTags.has(verdict.expectedOutbound)
            ? verdict.expectedOutbound
            : undefined)

        rows.push({
          service,
          expectedOutbound: verdict.expectedOutbound,
          actualOutbound: verdict.actualOutbound,
          fixTarget,
          domainCount: getServiceDomainCount(list),
        })
      }
    }

    return rows
  }, [services, scanResults, routeRules, outboundTags])

  const leakRowByService = useMemo(
    () => new Map(leakRows.map((row) => [row.service, row])),
    [leakRows],
  )

  // Keep selection pruned to currently-leaking AND fixable services (a service
  // can flip to OK on a re-scan, or get fixed and drop out of the table).
  const selectedLeaking = useMemo(() => {
    const next = new Set<string>()
    for (const service of selectedServices) {
      if (leakRowByService.get(service)?.fixTarget) {
        next.add(service)
      }
    }

    return next
  }, [selectedServices, leakRowByService])

  const runScan = useCallback(async () => {
    if (isScanning) {
      return
    }

    // Only scan services that actually have a testable entry (a domain/IP to probe).
    const testable = services.filter(([, list]) =>
      Boolean(getServiceLeakCheckTarget(list)),
    )
    if (testable.length === 0) {
      toast.warning(t("pages.leakScanner.messages.noTestable"), {
        richColors: true,
      })
      return
    }

    scanCancelledRef.current = false
    setScanCompleted(false)
    setSelectedServices(new Set())
    setScanResults({})
    setScanProgress({ done: 0, total: testable.length })

    let checked = 0

    await runWithConcurrency(
      testable,
      SCAN_CONCURRENCY,
      async ([service, list]: [string, ListConfig]) => {
        const target = getServiceLeakCheckTarget(list)
        if (!target) {
          return
        }

        setScanResults((previous) => ({
          ...previous,
          [service]: { status: "loading" },
        }))

        const verdict = await runServiceScan(target, (probe) =>
          postRoutingTest({ target: probe }),
        )

        setScanResults((previous) => ({ ...previous, [service]: verdict }))
        checked += 1
      },
      {
        onResult: () =>
          setScanProgress((previous) =>
            previous ? { ...previous, done: previous.done + 1 } : previous,
          ),
        shouldStop: () => scanCancelledRef.current,
      },
    )

    setScanProgress(null)

    if (scanCancelledRef.current || checked === 0) {
      return
    }

    setScanCompleted(true)
  }, [isScanning, services, t])

  const handleCancelScan = useCallback(() => {
    scanCancelledRef.current = true
  }, [])

  // Apply one fix per service by folding reassignServiceOutbound over the rules,
  // moving each leaking service back to its EXPECTED outbound, then staging the
  // result as a single config draft (committed later by the global Apply banner).
  const applyFixes = useCallback(
    (servicesToFix: string[]) => {
      if (!loadedConfig) {
        return
      }

      let nextRules: RouteRule[] = routeRules
      let movedCount = 0
      for (const service of servicesToFix) {
        const row = leakRowByService.get(service)
        if (!row || !row.fixTarget) {
          continue
        }
        nextRules = reassignServiceOutbound(nextRules, service, row.fixTarget)
        movedCount += 1
      }

      if (movedCount === 0) {
        setFixRequest(null)
        return
      }

      postConfigMutation.mutate(
        {
          data: {
            ...loadedConfig,
            route: { ...loadedConfig.route, rules: nextRules },
          },
        },
        {
          onSuccess: () => {
            // Drop the just-fixed services from results + selection so the table
            // shrinks to what still leaks; their stale verdicts no longer apply.
            setScanResults((previous) => {
              const next = { ...previous }
              for (const service of servicesToFix) {
                delete next[service]
              }

              return next
            })
            setSelectedServices((previous) => {
              const next = new Set(previous)
              for (const service of servicesToFix) {
                next.delete(service)
              }

              return next
            })
            setFixRequest(null)
            toast.success(
              t("pages.leakScanner.fix.success", { count: movedCount }),
              { richColors: true },
            )
          },
        },
      )
    },
    [loadedConfig, routeRules, leakRowByService, postConfigMutation, t],
  )

  // Only fixable rows (a real outbound to move to) participate in selection —
  // a row we cannot fix has no checkbox value and is never bulk-selected.
  const fixableServices = useMemo(
    () => leakRows.filter((row) => row.fixTarget).map((row) => row.service),
    [leakRows],
  )

  const selectionProps: DataTableSelection = {
    // Empty rowId = non-selectable row (DataTable disables that checkbox).
    rowIds: leakRows.map((row) => (row.fixTarget ? row.service : "")),
    selectedIds: selectedLeaking,
    selectionDisabled: configMutationPending || isScanning,
    selectAllAriaLabel: t("common.selection.selectAll"),
    selectRowAriaLabel: (rowId: string) =>
      t("common.selection.selectRow", { rowLabel: rowId }),
    selectAllTooltip: t("common.selection.selectAll"),
    onToggleRow: (rowId: string) => {
      setSelectedServices((previous) => {
        const next = new Set(previous)
        if (next.has(rowId)) {
          next.delete(rowId)
        } else {
          next.add(rowId)
        }

        return next
      })
    },
    onSelectAllVisible: (selectedAll: boolean) => {
      setSelectedServices(selectedAll ? new Set(fixableServices) : new Set())
    },
  }

  const tableRows = leakRows.map((row) => [
    <span className="font-mono font-medium" key={`${row.service}-name`}>
      {row.service}
    </span>,
    <LeakDescription
      actual={row.actualOutbound}
      expected={row.expectedOutbound}
      key={`${row.service}-status`}
      t={t}
    />,
    <span
      className="font-mono text-sm text-muted-foreground"
      key={`${row.service}-domains`}
    >
      {row.domainCount}
    </span>,
    <div className="flex justify-end" key={`${row.service}-fix`}>
      <Button
        disabled={configMutationPending || isScanning || !row.fixTarget}
        onClick={() => setFixRequest([row.service])}
        size="sm"
        variant="outline"
      >
        <Wrench className="mr-1 h-4 w-4" />
        {t("pages.leakScanner.fix.action")}
      </Button>
    </div>,
  ])

  // Preview rows for the confirm dialog: only services we can actually fix
  // (those with a resolved fixTarget), mapped to the destination outbound.
  const fixPreviewRows = useMemo<FixPreviewRow[]>(
    () =>
      (fixRequest ?? [])
        .map((service) => leakRowByService.get(service))
        .filter((row): row is LeakRow => Boolean(row?.fixTarget))
        .map((row) => ({
          service: row.service,
          actualOutbound: row.actualOutbound,
          targetOutbound: row.fixTarget as string,
          domainCount: row.domainCount,
        })),
    [fixRequest, leakRowByService],
  )

  return (
    <div className="space-y-6">
      <PageHeader
        description={t("pages.leakScanner.description")}
        title={t("pages.leakScanner.title")}
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
      ) : (
        <>
          <SectionCard
            terminalFilename="leak.scan"
            title={t("pages.leakScanner.scan.title")}
          >
            <p className="text-sm text-muted-foreground">
              {t("pages.leakScanner.scan.explainer")}
            </p>
            <div className="flex flex-wrap items-center gap-3">
              {isScanning ? (
                <>
                  <Button onClick={handleCancelScan} size="sm" variant="outline">
                    <X className="mr-1 h-4 w-4" />
                    {t("common.cancel")}
                  </Button>
                  <span
                    aria-live="polite"
                    className="font-mono text-xs text-muted-foreground"
                  >
                    {t("pages.leakScanner.scan.progress", {
                      done: scanProgress.done,
                      total: scanProgress.total,
                    })}
                  </span>
                </>
              ) : (
                <Button
                  disabled={services.length === 0 || configMutationPending}
                  onClick={() => void runScan()}
                  size="sm"
                  variant="default"
                >
                  <RadarIcon className="mr-1 h-4 w-4" />
                  {t("pages.leakScanner.scan.action")}
                </Button>
              )}

              {!isScanning && scanCompleted ? (
                leakRows.length > 0 ? (
                  <Badge size="xs" variant="destructive">
                    <ShieldAlert className="h-3 w-3" />
                    {t("pages.leakScanner.scan.summaryLeaking", {
                      count: leakRows.length,
                    })}
                  </Badge>
                ) : (
                  <Badge size="xs" variant="success">
                    <ShieldCheck className="h-3 w-3" />
                    {t("pages.leakScanner.scan.summaryClean")}
                  </Badge>
                )
              ) : null}
            </div>
          </SectionCard>

          {!isScanning && scanCompleted && leakRows.length === 0 ? (
            <ListPlaceholder
              description={t("pages.leakScanner.clean.description")}
              title={t("pages.leakScanner.clean.title")}
            />
          ) : null}

          {leakRows.length > 0 ? (
            <div className="space-y-3">
              {selectedLeaking.size > 0 ? (
                <BulkSelectionToolbar
                  countLabel={t("pages.leakScanner.bulk.selected", {
                    count: selectedLeaking.size,
                  })}
                >
                  <Button
                    disabled={configMutationPending || isScanning}
                    onClick={() => setFixRequest([...selectedLeaking])}
                    size="sm"
                    variant="default"
                  >
                    <Wrench className="mr-1 h-4 w-4" />
                    {t("pages.leakScanner.bulk.fixSelected")}
                  </Button>
                </BulkSelectionToolbar>
              ) : null}

              <DataTable
                headers={[
                  t("pages.leakScanner.headers.service"),
                  t("pages.leakScanner.headers.status"),
                  t("pages.leakScanner.headers.domains"),
                  t("pages.leakScanner.headers.fix"),
                ]}
                narrowColumns={[2]}
                rows={tableRows}
                selection={selectionProps}
              />
            </div>
          ) : null}
        </>
      )}

      <FixPreviewDialog
        isPending={postConfigMutation.isPending}
        onConfirm={() => {
          if (fixRequest) {
            applyFixes(fixRequest)
          }
        }}
        onOpenChange={(open) => {
          if (!open && !postConfigMutation.isPending) {
            setFixRequest(null)
          }
        }}
        open={fixRequest !== null}
        rows={fixPreviewRows}
        t={t}
      />
    </div>
  )
}

type TranslateFn = (key: string, options?: Record<string, unknown>) => string

/** Plain-language leak status: "Goes through {actual}, expected {expected}". */
function LeakDescription({
  actual,
  expected,
  t,
}: {
  actual: string
  expected: string
  t: TranslateFn
}) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5 text-sm">
      <ShieldAlert className="h-4 w-4 shrink-0 text-destructive" />
      <span>{t("pages.leakScanner.status.goesThrough")}</span>
      <Badge size="xs" variant="destructive">
        {actual}
      </Badge>
      <span className="text-muted-foreground">
        {t("pages.leakScanner.status.expected")}
      </span>
      <Badge size="xs" variant="success">
        {expected}
      </Badge>
    </span>
  )
}

type FixPreviewRow = {
  service: string
  /** Destination outbound the service will be moved to. */
  targetOutbound: string
  actualOutbound: string
  domainCount: number
}

/**
 * Confirmation dialog for moving services back to their expected outbound. Shows
 * one explicit line per service ("Move N domains of <service> from <actual> to
 * <expected>") so the user sees exactly what changes before anything is staged.
 * Mirrors the DeleteImpactDialog layout to match the design system.
 */
function FixPreviewDialog({
  isPending,
  onConfirm,
  onOpenChange,
  open,
  rows,
  t,
}: {
  isPending: boolean
  onConfirm: () => void
  onOpenChange: (open: boolean) => void
  open: boolean
  rows: FixPreviewRow[]
  t: TranslateFn
}) {
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 font-mono">
            <Wrench className="size-4 text-primary" />
            {t("pages.leakScanner.fixDialog.title", { count: rows.length })}
          </DialogTitle>
          <DialogDescription>
            {t("pages.leakScanner.fixDialog.description")}
          </DialogDescription>
        </DialogHeader>

        {rows.length > 0 ? (
          <div className="max-h-72 overflow-y-auto rounded-lg border bg-muted/30 p-3">
            <ul className="space-y-2 text-sm leading-5">
              {rows.map((row) => (
                <li className="flex gap-2" key={row.service}>
                  <span
                    aria-hidden="true"
                    className="mt-[0.45rem] size-1.5 shrink-0 rounded-full bg-primary/70"
                  />
                  <div className="min-w-0 space-y-0.5">
                    <div>
                      {t("pages.leakScanner.fixDialog.movePrefix", {
                        count: row.domainCount,
                      })}{" "}
                      <strong className="font-mono">{row.service}</strong>
                    </div>
                    <div className="flex flex-wrap items-center gap-1 border-l border-border pl-3 font-mono text-xs leading-4 text-muted-foreground">
                      <span>{row.actualOutbound}</span>
                      <ArrowRight className="size-3 shrink-0 text-primary" />
                      <span>{row.targetOutbound}</span>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <DialogFooter>
          <DialogClose render={<Button disabled={isPending} variant="outline" />}>
            {t("common.cancel")}
          </DialogClose>
          <Button disabled={isPending} onClick={onConfirm} variant="default">
            {isPending ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : null}
            {t("pages.leakScanner.fixDialog.confirm", { count: rows.length })}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
