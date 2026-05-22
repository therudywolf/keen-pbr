import { useTranslation } from "react-i18next"

import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

/** Default number of chips rendered inline before collapsing into a "+N" pill. */
const DEFAULT_INLINE_LIMIT = 6

/**
 * A single terminal-style list chip: a colored 2-3 letter prefix block followed
 * by the full list name in mono. The prefix colour is derived from the name so
 * the same list always looks the same.
 */
function ListChip({ name }: { name: string }) {
  return (
    <span
      className="inline-flex max-w-full items-center overflow-hidden rounded-md border border-border bg-muted/40 font-mono text-[11px] leading-none"
      title={name}
    >
      <span
        className={cn(
          "shrink-0 px-1.5 py-1 font-semibold tracking-wider uppercase",
          prefixToneClass(name),
        )}
      >
        {chipPrefix(name)}
      </span>
      <span className="truncate px-1.5 py-1 text-foreground">{name}</span>
    </span>
  )
}

/**
 * Renders a set of matched list names as a scannable, wrapped row of chips.
 *
 * When the set exceeds `inlineLimit`, the surplus collapses into a `+N` pill
 * that opens a popover with the complete list. An empty set renders a muted
 * dash so table cells never look broken.
 */
export function ListChips({
  lists,
  inlineLimit = DEFAULT_INLINE_LIMIT,
  className,
}: {
  lists: readonly string[]
  inlineLimit?: number
  className?: string
}) {
  const { t } = useTranslation()
  const cleaned = lists.filter((name) => name.trim().length > 0)

  if (cleaned.length === 0) {
    return <span className="text-sm text-muted-foreground">{t("common.noneShort")}</span>
  }

  const visible = cleaned.slice(0, inlineLimit)
  const hidden = cleaned.slice(inlineLimit)

  const countLabel =
    cleaned.length === 1
      ? t("common.listChips.countSingular")
      : t("common.listChips.count", { count: cleaned.length })

  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <span className="font-mono text-[11px] text-muted-foreground">
        {countLabel}
      </span>
      <div className="flex flex-wrap items-center gap-1">
        {visible.map((name) => (
          <ListChip key={name} name={name} />
        ))}
        {hidden.length > 0 ? (
          <Popover>
            <PopoverTrigger
              className="inline-flex items-center rounded-md border border-dashed border-border bg-transparent px-1.5 py-1 font-mono text-[11px] leading-none text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary focus-visible:border-primary focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
              type="button"
            >
              +{hidden.length}
            </PopoverTrigger>
            <PopoverContent align="start" className="w-auto max-w-xs">
              <div className="mb-1.5 font-mono text-[11px] text-muted-foreground">
                {t("common.listChips.allLists", { count: cleaned.length })}
              </div>
              <div className="flex max-h-64 flex-wrap gap-1 overflow-y-auto">
                {cleaned.map((name) => (
                  <ListChip key={name} name={name} />
                ))}
              </div>
            </PopoverContent>
          </Popover>
        ) : null}
      </div>
    </div>
  )
}

/** First three (uppercase) alphanumerics of a name, used as the chip prefix. */
function chipPrefix(name: string): string {
  const compact = name.replace(/[^a-zA-Z0-9]/g, "")
  return (compact.slice(0, 3) || name.slice(0, 3)).toUpperCase()
}

/**
 * Deterministically maps a name to one of the palette accent colours so chips
 * stay visually distinct without going off-palette.
 */
function prefixToneClass(name: string): string {
  const tones = [
    "text-primary",
    "text-success",
    "text-warning",
    "text-accent-foreground",
    "text-chart-5",
  ]
  let hash = 0
  for (let i = 0; i < name.length; i += 1) {
    hash = (hash * 31 + name.charCodeAt(i)) | 0
  }
  return tones[Math.abs(hash) % tones.length]
}
