import type { ReactNode } from "react"

import {
  Card,
  CardContent,
  CardDescription,
  CardTerminalBar,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

/**
 * A terminal-window styled panel: a title bar with traffic-light dots and a
 * monospace filename, a `//`-prefixed mono section heading, and the content.
 *
 * `terminalFilename` controls the label in the title bar — pass a short,
 * file-like identifier (e.g. `runtime.status`). When omitted, the title is
 * slugified into a `.panel` filename so every panel still reads as a window.
 */
export function SectionCard({
  title,
  children,
  action,
  description,
  className,
  contentClassName,
  terminalFilename,
}: {
  title: string
  children: ReactNode
  action?: ReactNode
  description?: ReactNode
  className?: string
  contentClassName?: string
  terminalFilename?: string
}) {
  return (
    <Card className={cn("gap-0 py-0", className)}>
      <CardTerminalBar filename={terminalFilename ?? toTerminalFilename(title)} />
      <CardContent className={cn("space-y-3 py-4", contentClassName)}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <h2 className="font-mono text-sm font-semibold tracking-tight text-foreground">
              <span className="text-primary">//</span> {title}
            </h2>
            {description ? (
              <CardDescription>{description}</CardDescription>
            ) : null}
          </div>
          {action ? <div className="shrink-0">{action}</div> : null}
        </div>
        {children}
      </CardContent>
    </Card>
  )
}

/** Slugifies a human title into a lowercase dotted `.panel` filename. */
function toTerminalFilename(title: string): string {
  const slug = title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")

  return `${slug || "section"}.panel`
}
