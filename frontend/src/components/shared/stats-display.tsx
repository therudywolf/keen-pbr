import { useTranslation } from "react-i18next"

/**
 * Compact list-entry counts rendered as `total / ipv4 / ipv6` in mono. A title
 * tooltip spells out which number is which, since the slash form alone is terse.
 */
export function StatsDisplay({
  totalHosts,
  ipv4Subnets,
  ipv6Subnets,
}: {
  totalHosts: number | string
  ipv4Subnets: number | string
  ipv6Subnets: number | string
}) {
  const { t } = useTranslation()

  return (
    <span
      className="font-mono text-sm text-muted-foreground tabular-nums"
      title={t("common.statsDisplay.tooltip", {
        total: totalHosts,
        ipv4: ipv4Subnets,
        ipv6: ipv6Subnets,
      })}
    >
      <span className="text-foreground">{totalHosts}</span>
      <span className="text-muted-foreground/60"> / </span>
      {ipv4Subnets}
      <span className="text-muted-foreground/60"> / </span>
      {ipv6Subnets}
    </span>
  )
}
