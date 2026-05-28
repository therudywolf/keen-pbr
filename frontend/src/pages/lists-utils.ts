import type { ConfigObject } from "@/api/generated/model/configObject"

export type ListDeleteImpact = {
  routeRuleIndexes: number[]
  removedRouteRuleIndexes: number[]
}

export function getListDeleteImpact(
  config: ConfigObject,
  listIds: Iterable<string>
): ListDeleteImpact {
  const listIdSet = new Set(listIds)
  const routeRuleIndexes: number[] = []
  const removedRouteRuleIndexes: number[] = []

  for (const [index, rule] of (config.route?.rules ?? []).entries()) {
    const beforeLists = rule.list ?? []
    const afterLists = beforeLists.filter((name) => !listIdSet.has(name))

    if (afterLists.length !== beforeLists.length) {
      routeRuleIndexes.push(index)
    }

    if (beforeLists.length > 0 && afterLists.length === 0) {
      removedRouteRuleIndexes.push(index)
    }
  }

  return {
    routeRuleIndexes,
    removedRouteRuleIndexes,
  }
}

export function buildUpdatedConfigForListsDelete(
  config: ConfigObject,
  listIds: string[]
): ConfigObject {
  return listIds.reduce(
    (acc, id) => buildUpdatedConfigForListDelete(acc, id),
    config
  )
}

export function buildUpdatedConfigForListDelete(
  config: ConfigObject,
  listId: string
): ConfigObject {
  const nextLists = { ...(config.lists ?? {}) }
  delete nextLists[listId]

  return {
    ...config,
    lists: nextLists,
    route: {
      ...config.route,
      rules: (config.route?.rules ?? [])
        .map((rule) => ({
          ...rule,
          list: (rule.list ?? []).filter((name) => name !== listId),
        }))
        .filter((rule) => rule.list.length > 0),
    },
  }
}
