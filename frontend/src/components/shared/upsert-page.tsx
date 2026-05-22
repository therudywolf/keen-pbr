import type { ReactNode } from "react"

import { PageHeader } from "@/components/shared/page-header"
import {
  Card,
  CardContent,
  CardDescription,
  CardTerminalBar,
} from "@/components/ui/card"
import { useIsMobile } from "@/hooks/use-mobile"

export function UpsertPage({
  title,
  description,
  cardTitle,
  cardDescription,
  children,
}: {
  title: string
  description: string
  cardTitle: string
  cardDescription: string
  children: ReactNode
}) {
  const isMobile = useIsMobile()

  return (
    <div className="space-y-5 md:space-y-6">
      <PageHeader description={description} title={title} />
      <Card className="gap-0 py-0" size={isMobile ? "sm" : "default"}>
        <CardTerminalBar filename={toTerminalFilename(cardTitle)} />
        <CardContent className="space-y-4 py-4 group-data-[size=sm]/card:py-3">
          <div className="space-y-1">
            <h2 className="font-mono text-sm font-semibold tracking-tight text-foreground">
              <span className="text-primary">//</span> {cardTitle}
            </h2>
            <CardDescription>{cardDescription}</CardDescription>
          </div>
          {children}
        </CardContent>
      </Card>
    </div>
  )
}

/** Slugifies a human title into a lowercase dotted `.cfg` filename. */
function toTerminalFilename(title: string): string {
  const slug = title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")

  return `${slug || "entry"}.cfg`
}
