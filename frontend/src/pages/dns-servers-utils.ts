import type { ConfigObject } from "@/api/generated/model/configObject"

export type DnsServerDeleteImpact = {
  matchingRuleIndexes: number[]
  usesFallback: boolean
}

export function getDnsServerDeleteImpact(
  config: ConfigObject,
  serverTags: Iterable<string>
): DnsServerDeleteImpact {
  const tagSet = new Set(serverTags)
  const rules = config.dns?.rules ?? []
  const fallback = config.dns?.fallback ?? []

  return {
    matchingRuleIndexes: rules.flatMap((rule, index) =>
      tagSet.has(rule.server) ? [index] : []
    ),
    usesFallback: fallback.some((tag) => tagSet.has(tag)),
  }
}

export function buildUpdatedConfigForDnsServersDelete(
  config: ConfigObject,
  serverTags: string[],
  stripReferences: boolean
): ConfigObject {
  const tagSet = new Set(serverTags)
  const dnsConfig = config.dns
  const allRules = dnsConfig?.rules ?? []
  const fallbackServers = dnsConfig?.fallback ?? []

  return {
    ...config,
    dns: {
      ...(dnsConfig ?? {}),
      servers: (dnsConfig?.servers ?? []).filter(
        (server) => !tagSet.has(server.tag)
      ),
      rules: stripReferences
        ? allRules.filter((rule) => !tagSet.has(rule.server))
        : allRules,
      fallback: stripReferences
        ? fallbackServers.filter((tag) => !tagSet.has(tag))
        : fallbackServers,
    },
  }
}
