import { ArrowRight, Pencil, Plus, Trash2 } from "lucide-react"
import type { ReactNode } from "react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import type { getConfigResponse } from "@/api/generated/keen-api"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import { DnsServerType } from "@/api/generated/model/dnsServerType"
import { usePostConfigMutation, useConfigMutationPending } from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { DataTable, type DataTableSelection } from "@/components/shared/data-table"
import {
  DeleteImpactDialog,
  type DeleteImpactItem,
} from "@/components/shared/delete-impact-dialog"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  buildUpdatedConfigForDnsServersDelete,
  getDnsServerDeleteImpact,
  type DnsServerDeleteImpact,
} from "@/pages/dns-servers-utils"

export function DnsServersPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const configMutationPending = useConfigMutationPending()
  const configQuery = useGetConfig()
  const postConfigMutation = usePostConfigMutation()

  const config = getConfigData(configQuery.data)
  const dnsServers = useMemo(() => config?.dns?.servers ?? [], [config])

  const rowIdsRaw = dnsServers.map((server) => server.tag)

  const [selectedDnsServerTags, setSelectedDnsServerTags] = useState<Set<string>>(
    () => new Set(),
  )
  const [deleteRequest, setDeleteRequest] = useState<{
    tags: string[]
    impact: DnsServerDeleteImpact
    config: ConfigObject
    clearSelectionOnSuccess: boolean
  } | null>(null)
  const [deletePreview, setDeletePreview] = useState<typeof deleteRequest>(null)
  const visibleDeleteRequest = deleteRequest ?? deletePreview

  const validDnsServerTagSet = useMemo(
    () => new Set(dnsServers.map((server) => server.tag)),
    [dnsServers],
  )

  const selectedDnsServerTagsResolved = useMemo(() => {
    const next = new Set<string>()
    for (const tag of selectedDnsServerTags) {
      if (validDnsServerTagSet.has(tag)) {
        next.add(tag)
      }
    }

    return next
  }, [selectedDnsServerTags, validDnsServerTagSet])

  const dnsServerSelectionProps: DataTableSelection = {
    rowIds: rowIdsRaw,
    selectedIds: selectedDnsServerTagsResolved,
    selectionDisabled: configMutationPending,
    selectAllAriaLabel: t("common.selection.selectAll"),
    selectRowAriaLabel: (rowTag: string) =>
      t("common.selection.selectRow", { rowLabel: rowTag }),
    selectAllTooltip: t("common.selection.selectAll"),
    onToggleRow: (tag: string) => {
      setSelectedDnsServerTags((previous) => {
        const next = new Set(previous)
        if (next.has(tag)) {
          next.delete(tag)
        } else {
          next.add(tag)
        }

        return next
      })
    },
    onSelectAllVisible: (selectedAll: boolean) => {
      setSelectedDnsServerTags(
        selectedAll ? new Set(rowIdsRaw) : new Set(),
      )
    },
  }

  const deleteServersBulk = () => {
    if (!config || selectedDnsServerTagsResolved.size === 0) {
      return
    }

    const selectedTags = [...selectedDnsServerTagsResolved]
    const request = {
      tags: selectedTags,
      impact: getDnsServerDeleteImpact(config, selectedTags),
      config,
      clearSelectionOnSuccess: true,
    }
    setDeletePreview(request)
    setDeleteRequest(request)
  }

  const deleteServer = (serverTag: string) => {
    if (!config) {
      return
    }

    const request = {
      tags: [serverTag],
      impact: getDnsServerDeleteImpact(config, [serverTag]),
      config,
      clearSelectionOnSuccess: false,
    }
    setDeletePreview(request)
    setDeleteRequest(request)
  }

  const confirmDelete = () => {
    if (!config || !deleteRequest) {
      return
    }

    const updatedConfig = buildUpdatedConfigForDnsServersDelete(
      config,
      deleteRequest.tags,
      true,
    )

    postConfigMutation.mutate(
      { data: updatedConfig },
      {
        onSuccess: () => {
          if (deleteRequest.clearSelectionOnSuccess) {
            setSelectedDnsServerTags(new Set())
          }
          setDeleteRequest(null)
        },
      },
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        actions={
          <Button disabled={configMutationPending} onClick={() => navigate("/dns-servers/create")}>
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.dnsServers.actions.add")}
          </Button>
        }
        description={t("pages.dnsServers.description")}
        title={t("pages.dnsServers.title")}
      />

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {configQuery.isLoading ? (
        <TableSkeleton />
      ) : configQuery.isError ? (
        <ListPlaceholder
          description={t("pages.dnsServers.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : dnsServers.length === 0 ? (
        <ListPlaceholder
          description={t("pages.dnsServers.empty.description")}
          title={t("pages.dnsServers.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          {selectedDnsServerTagsResolved.size > 0 ? (
            <BulkSelectionToolbar
              countLabel={t("pages.dnsServers.bulk.selected", {
                count: selectedDnsServerTagsResolved.size,
              })}
            >
              <Button
                disabled={configMutationPending}
                onClick={() => deleteServersBulk()}
                size="sm"
                variant="destructive"
              >
                <Trash2 className="mr-1 h-4 w-4" />
                {t("pages.dnsServers.bulk.delete")}
              </Button>
            </BulkSelectionToolbar>
          ) : null}
          <DataTable
            headers={[
              t("pages.dnsServers.headers.name"),
              t("pages.dnsServers.headers.address"),
              t("pages.dnsServers.headers.outbound"),
              t("pages.dnsServers.headers.actions"),
            ]}
            narrowColumns={[0]}
            rows={dnsServers.map((server) => [
              <div className="font-mono font-medium" key={`${server.tag}-tag`}>
                {server.tag}
              </div>,
              <span
                className="font-mono text-sm text-muted-foreground"
                key={`${server.tag}-address`}
              >
                {server.type === DnsServerType.keenetic
                  ? t("pages.dnsServers.keeneticAddress")
                  : server.address}
              </span>,
              <Badge
                className="font-mono"
                key={`${server.tag}-detour`}
                variant={server.detour ? "outline" : "secondary"}
              >
                {server.detour || t("pages.dnsServers.none")}
              </Badge>,
              <ActionButtons
                actions={[
                  {
                    disabled: configMutationPending,
                    icon: <Pencil className="h-4 w-4" />,
                    label: t("common.edit"),
                    onClick: () =>
                      navigate(
                        `/dns-servers/${encodeURIComponent(server.tag)}/edit`
                      ),
                  },
                  {
                    disabled: configMutationPending,
                    icon: <Trash2 className="h-4 w-4" />,
                    label: t("common.delete"),
                    onClick: () => deleteServer(server.tag),
                  },
                ]}
                key={`${server.tag}-actions`}
              />,
            ])}
            selection={dnsServerSelectionProps}
          />
        </div>
      )}
      <DeleteImpactDialog
        confirmLabel={t("pages.dnsServers.deleteDialog.confirm")}
        description={t("pages.dnsServers.deleteDialog.description", {
          tags: visibleDeleteRequest?.tags.join(", ") ?? "",
        })}
        impactItems={
          visibleDeleteRequest
            ? getDnsServerDeleteImpactItems(
                visibleDeleteRequest.config,
                visibleDeleteRequest.tags,
                visibleDeleteRequest.impact,
                t,
              )
            : []
        }
        isPending={postConfigMutation.isPending}
        onConfirm={confirmDelete}
        onOpenChange={(open) => {
          if (!open && !postConfigMutation.isPending) {
            setDeleteRequest(null)
          }
        }}
        open={deleteRequest !== null}
        title={t("pages.dnsServers.deleteDialog.title")}
      />
    </div>
  )
}

function getDnsServerDeleteImpactItems(
  config: ConfigObject | undefined,
  serverTags: string[],
  impact: DnsServerDeleteImpact,
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  const items: DeleteImpactItem[] = []

  for (const tag of serverTags) {
    items.push({
      label: (
        <>
          {t("pages.dnsServers.deleteDialog.items.serverPrefix")}{" "}
          <strong className="font-mono">{tag}</strong>{" "}
          {t("pages.dnsServers.deleteDialog.items.serverSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.matchingRuleIndexes) {
    items.push({
      label: t("pages.dnsServers.deleteDialog.items.dnsRule", {
        number: index + 1,
      }),
      details: getDnsRuleDetails(config?.dns?.rules?.[index], t),
    })
  }

  if (impact.usesFallback) {
    const fallback = config?.dns?.fallback ?? []
    items.push({
      label: t("pages.dnsServers.deleteDialog.items.fallback"),
      details: [
        formatDetail(
          t("pages.dnsRules.fallback.title"),
          <ChangeValue
            after={formatListValue(
              fallback.filter((tag) => !serverTags.includes(tag)),
              t,
            )}
            before={formatListValue(fallback, t)}
          />,
        ),
      ],
    })
  }

  return items
}

function getDnsRuleDetails(
  rule: DnsRule | undefined,
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  if (!rule) {
    return []
  }

  return [
    formatDetail(
      t("pages.dnsRules.criteriaLabels.lists"),
      formatListValue(rule.list, t),
    ),
    formatDetail(t("pages.dnsRules.headers.serverTag"), rule.server),
  ]
}

function formatDetail(label: string, value: ReactNode) {
  return (
    <>
      {label}: {value}
    </>
  )
}

function formatListValue(
  values: string[],
  t: (key: string, options?: Record<string, unknown>) => string,
) {
  return values.length > 0 ? values.join(", ") : t("common.noneShort")
}

function ChangeValue({ after, before }: { after: string; before: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1 align-middle leading-4">
      <span className="min-w-0 truncate">{before}</span>
      <ArrowRight className="mt-px size-3 shrink-0 text-primary" />
      <span className="min-w-0 truncate">{after}</span>
    </span>
  )
}

function getConfigData(response: getConfigResponse | undefined) {
  if (!response || response.status !== 200) {
    return undefined
  }

  return response.data.config
}
