"use client"

import type { ComponentProps } from "react"
import { LayoutGridIcon, SettingsIcon, WaypointsIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { LanguageSelector } from "@/components/language-selector"
import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { ThemeSelector } from "@/components/theme-selector"
import { NavMain } from "@/components/nav-main"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
} from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"

export function AppSidebar(props: ComponentProps<typeof Sidebar>) {
  const { isMobile, toggleSidebar } = useSidebar()
  const { t } = useTranslation()

  const data = {
    navMain: [
      {
        title: t("nav.groups.overview"),
        url: "#",
        icon: LayoutGridIcon,
        items: [
          {
            title: t("nav.items.systemMonitor"),
            url: "/",
          },
          {
            title: t("nav.items.metrics"),
            url: "/metrics",
          },
        ],
      },
      {
        title: t("nav.groups.routing"),
        url: "#",
        icon: WaypointsIcon,
        items: [
          {
            title: t("nav.items.services"),
            url: "/services",
          },
          {
            title: t("nav.items.outbounds"),
            url: "/outbounds",
          },
          {
            title: t("nav.items.routingRules"),
            url: "/routing-rules",
          },
          {
            title: t("nav.items.lists"),
            url: "/lists",
          },
        ],
      },
      {
        title: t("nav.groups.settings"),
        url: "#",
        icon: SettingsIcon,
        items: [
          {
            title: t("nav.items.settings"),
            url: "/general",
          },
        ],
      },
    ],
  }

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader className={isMobile ? "border-b px-4 py-2" : "border-b"}>
        <SidebarMenuHeader isMobile={isMobile} onMenuClick={toggleSidebar} />
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={data.navMain} />
      </SidebarContent>
      <SidebarFooter className={isMobile ? "border-t px-4 py-3" : "border-t"}>
        <div className="space-y-3">
          <LanguageSelector />
          <ThemeSelector />
          <div className="px-1 pt-1 font-mono text-[10px] leading-relaxed text-muted-foreground/70">
            Forest-<span className="text-primary/80">PBR</span>
            <br />
            forest-pbr core · GPLv3 ⌁
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}

function SidebarMenuHeader({
  isMobile,
  onMenuClick,
}: {
  isMobile: boolean
  onMenuClick: () => void
}) {
  if (isMobile) {
    return <AppBrandHeader onMenuClick={onMenuClick} />
  }

  return <AppBrandHeader />
}
