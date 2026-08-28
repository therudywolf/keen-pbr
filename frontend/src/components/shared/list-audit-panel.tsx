import { useQuery } from "@tanstack/react-query"
import { AlertTriangle, ChevronDown, ChevronRight, EyeOff, Unplug } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import type { ApiError } from "@/api/client"
import { apiFetch } from "@/api/client"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

/** One finding from `GET /api/lists/audit`. */
export interface ListAdvisory {
  kind: "oversized_range" | "shadowed_domain" | "unused_list"
  list: string
  entry: string
  message: string
  /** oversized_range: IPv4 addresses covered; 0 for IPv6. */
  addresses?: number
  /** oversized_range: the CIDR prefix length. */
  prefix_length?: number
  /** shadowed_domain: the list being shadowed. */
  other_list?: string
  /** shadowed_domain: the entry being shadowed. */
  other_entry?: string
  /** unused_list: inline entries the list holds. */
  entry_count?: number
}

interface ListAuditResponse {
  advisories: ListAdvisory[]
  note: string
}

type AuditResult =
  | { available: true; data: ListAuditResponse }
  | { available: false }

const LIST_AUDIT_QUERY_KEY = ["/api/lists/audit"] as const

async function fetchListAudit(signal: AbortSignal): Promise<AuditResult> {
  try {
    const response = await apiFetch<{ data: ListAuditResponse; status: number }>(
      "/api/lists/audit",
      { method: "GET", signal },
    )
    return { available: true, data: response.data }
  } catch (error) {
    // Older daemons don't ship this endpoint; a 404 means "not available",
    // not a failure worth showing the operator.
    if ((error as ApiError | undefined)?.status === 404) {
      return { available: false }
    }
    throw error
  }
}

const KIND_ORDER: ListAdvisory["kind"][] = [
  "shadowed_domain",
  "oversized_range",
  "unused_list",
]

const KIND_META: Record<
  ListAdvisory["kind"],
  { icon: typeof AlertTriangle; tone: string }
> = {
  // A shadowed domain actively sends traffic the wrong way — the only kind
  // that is a live misroute rather than a latent risk.
  shadowed_domain: { icon: EyeOff, tone: "text-destructive" },
  oversized_range: { icon: AlertTriangle, tone: "text-amber-500" },
  unused_list: { icon: Unplug, tone: "text-muted-foreground" },
}

function formatAddresses(count: number | undefined): string {
  if (!count) return ""
  return count.toLocaleString()
}

/**
 * Advisory findings about the lists in this config.
 *
 * These never block a save — each is a judgement call, not an error — so the
 * panel stays collapsed until the operator opens it and never interrupts a
 * workflow. It renders nothing at all when the audit is clean or the daemon
 * predates the endpoint.
 */
export function ListAuditPanel() {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)

  const auditQuery = useQuery({
    queryKey: LIST_AUDIT_QUERY_KEY,
    queryFn: ({ signal }) => fetchListAudit(signal),
  })

  const grouped = useMemo(() => {
    const result = auditQuery.data
    if (!result?.available) return []
    const byKind = new Map<ListAdvisory["kind"], ListAdvisory[]>()
    for (const advisory of result.data.advisories) {
      const bucket = byKind.get(advisory.kind) ?? []
      bucket.push(advisory)
      byKind.set(advisory.kind, bucket)
    }
    return KIND_ORDER.filter((kind) => byKind.has(kind)).map((kind) => ({
      kind,
      items: byKind.get(kind) ?? [],
    }))
  }, [auditQuery.data])

  const total = grouped.reduce((sum, group) => sum + group.items.length, 0)

  if (auditQuery.isLoading || total === 0) {
    return null
  }

  return (
    <div className="rounded-lg border border-border/60 bg-card/40">
      <button
        aria-expanded={expanded}
        className="flex w-full items-center gap-2 px-4 py-3 text-left"
        onClick={() => setExpanded((value) => !value)}
        type="button"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
        <AlertTriangle className="h-4 w-4 shrink-0 text-amber-500" />
        <span className="text-sm font-medium">
          {t("pages.lists.audit.title")}
        </span>
        <Badge className="ml-1" variant="secondary">
          {total}
        </Badge>
        <span className="ml-auto text-xs text-muted-foreground">
          {t("pages.lists.audit.advisoryOnly")}
        </span>
      </button>

      {expanded ? (
        <div className="space-y-4 border-t border-border/60 px-4 py-3">
          {grouped.map((group) => {
            const Icon = KIND_META[group.kind].icon
            return (
              <div key={group.kind}>
                <div className="mb-2 flex items-center gap-2">
                  <Icon
                    className={`h-4 w-4 shrink-0 ${KIND_META[group.kind].tone}`}
                  />
                  <span className="text-sm font-medium">
                    {t(`pages.lists.audit.kind.${group.kind}.title`)}
                  </span>
                  <Badge variant="outline">{group.items.length}</Badge>
                </div>
                <p className="mb-2 text-xs text-muted-foreground">
                  {t(`pages.lists.audit.kind.${group.kind}.description`)}
                </p>
                <ul className="space-y-1">
                  {group.items.map((advisory) => (
                    <li
                      className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs"
                      key={`${advisory.kind}-${advisory.list}-${advisory.entry}-${advisory.other_entry ?? ""}`}
                    >
                      <Badge className="font-mono" variant="secondary">
                        {advisory.list}
                      </Badge>
                      {advisory.entry ? (
                        <code className="font-mono text-muted-foreground">
                          {advisory.entry}
                        </code>
                      ) : null}
                      {advisory.kind === "oversized_range" ? (
                        <span className="text-muted-foreground">
                          {advisory.addresses
                            ? t("pages.lists.audit.addresses", {
                                count: advisory.addresses,
                                formatted: formatAddresses(advisory.addresses),
                              })
                            : `IPv6 /${advisory.prefix_length}`}
                        </span>
                      ) : null}
                      {advisory.kind === "shadowed_domain" ? (
                        <span className="text-muted-foreground">
                          {t("pages.lists.audit.shadows")}{" "}
                          <code className="font-mono">
                            {advisory.other_entry}
                          </code>{" "}
                          <Badge className="font-mono" variant="outline">
                            {advisory.other_list}
                          </Badge>
                        </span>
                      ) : null}
                      {advisory.kind === "unused_list" ? (
                        <span className="text-muted-foreground">
                          {t("pages.lists.audit.entries", {
                            count: advisory.entry_count ?? 0,
                          })}
                        </span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
          <Button
            className="h-auto p-0 text-xs"
            onClick={() => auditQuery.refetch()}
            variant="link"
          >
            {t("pages.lists.audit.recheck")}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
