import { CircleSlash, Route, RouteOff } from "lucide-react"

export function IpSetStateIcon({
  targetInLists,
  inIpset,
}: {
  targetInLists: boolean
  inIpset?: boolean | null
}) {
  if (inIpset === undefined || inIpset === null) {
    return <CircleSlash className="mx-auto h-4 w-4 text-muted-foreground" />
  }
  if (targetInLists && inIpset) {
    return <Route className="mx-auto h-5 w-5 text-success" />
  }
  if (!targetInLists && !inIpset) {
    return <RouteOff className="mx-auto h-5 w-5 text-muted-foreground" />
  }
  if (!targetInLists && inIpset) {
    return <Route className="mx-auto h-5 w-5 text-warning" />
  }
  return <RouteOff className="mx-auto h-5 w-5 text-destructive" />
}
