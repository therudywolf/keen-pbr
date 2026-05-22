import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

/** Semantic tone for a metric — drives the gauge-bar and value colour. */
export type MetricTone = "neutral" | "info" | "healthy" | "warning" | "critical"

const toneBarClass: Record<MetricTone, string> = {
  neutral: "bg-muted-foreground/50",
  info: "bg-primary",
  healthy: "bg-success",
  warning: "bg-warning",
  critical: "bg-destructive",
}

const toneBorderClass: Record<MetricTone, string> = {
  neutral: "border-border",
  info: "border-primary/30",
  healthy: "border-success/30",
  warning: "border-warning/40",
  critical: "border-destructive/40",
}

const toneValueClass: Record<MetricTone, string> = {
  neutral: "text-foreground",
  info: "text-foreground",
  healthy: "text-foreground",
  warning: "text-warning",
  critical: "text-destructive",
}

/**
 * A Reference-A style metric card: an UPPERCASE mono label, a large value with
 * an optional unit, and a thin gauge bar along the bottom edge that fills
 * proportionally. `fill` is clamped to 0..1; omit it for a non-gauge metric.
 */
export function MetricCard({
  label,
  value,
  unit,
  tone = "neutral",
  fill,
  hint,
}: {
  label: string
  value: ReactNode
  unit?: string
  tone?: MetricTone
  fill?: number
  hint?: ReactNode
}) {
  const clampedFill =
    typeof fill === "number"
      ? Math.max(0, Math.min(1, fill))
      : undefined

  return (
    <div
      className={cn(
        "relative flex flex-col gap-1 overflow-hidden rounded-lg border bg-card/60 px-3 pt-2.5 pb-3.5",
        toneBorderClass[tone],
      )}
    >
      <span className="font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
        {label}
      </span>
      <div className="flex items-baseline gap-1">
        <span
          className={cn(
            "font-mono text-2xl leading-none font-semibold tabular-nums",
            toneValueClass[tone],
          )}
        >
          {value}
        </span>
        {unit ? (
          <span className="font-mono text-[11px] text-muted-foreground">
            {unit}
          </span>
        ) : null}
      </div>
      {hint ? (
        <span className="font-mono text-[10px] text-muted-foreground">{hint}</span>
      ) : null}
      {/* Gauge bar pinned to the bottom edge. */}
      <span className="absolute inset-x-0 bottom-0 h-1 bg-foreground/8">
        {clampedFill !== undefined ? (
          <span
            className={cn(
              "block h-full transition-[width]",
              toneBarClass[tone],
            )}
            style={{ width: `${clampedFill * 100}%` }}
          />
        ) : (
          <span className={cn("block h-full w-full opacity-50", toneBarClass[tone])} />
        )}
      </span>
    </div>
  )
}
