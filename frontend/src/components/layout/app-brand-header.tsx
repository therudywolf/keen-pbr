import { MenuIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import logoUrl from "@/assets/logo.svg"
import { IconButtonWithTooltip } from "@/components/shared/icon-button-with-tooltip"
import { cn } from "@/lib/utils"

export function AppBrandHeader({
  onMenuClick,
  className = "",
}: {
  onMenuClick?: () => void
  variant?: "sidebar" | "topbar"
  className?: string
}) {
  const { t } = useTranslation()

  return (
    <div
      className={cn(
        "flex items-center gap-3 px-0 py-0",
        className
      )}
    >
      {onMenuClick ? (
        <IconButtonWithTooltip
          className="size-8 shrink-0 rounded-md border bg-muted text-muted-foreground shadow-none hover:bg-muted"
          label={t("brand.openMenu")}
          onClick={onMenuClick}
          size="icon"
          variant="ghost"
        >
          <MenuIcon className="h-4 w-4" />
        </IconButtonWithTooltip>
      ) : null}
      <div className="flex size-10 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-primary/30 bg-primary/10 p-1.5">
        <img alt={t("brand.logoAlt")} className="size-full object-contain" src={logoUrl} />
      </div>
      <div className="grid min-w-0 flex-1 text-left leading-tight">
        <span className="truncate font-mono text-base font-semibold tracking-tight">
          Forest-<span className="text-primary">PBR</span>
        </span>
        <span className="truncate font-mono text-[11px] text-muted-foreground">
          {t("brand.tagline")}
        </span>
      </div>
    </div>
  )
}
