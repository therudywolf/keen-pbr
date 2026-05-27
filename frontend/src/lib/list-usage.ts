export type ListUsageRef = {
  ruleIndex: number
  target: string
}

/**
 * Returns the rules in `rules` that reference `listName`, with a structured
 * `{ ruleIndex, target }` describing what each match points at. The `target`
 * is whatever you pluck out of the rule (e.g. routing rule outbound, DNS
 * rule server). Skips `excludeRuleIndex` so editor pages can ignore the
 * rule they're currently editing.
 */
export function getRulesUsingList<T>(
  listName: string,
  rules: T[],
  getListNames: (rule: T) => string[] | undefined,
  getTarget: (rule: T) => string,
  excludeRuleIndex?: number
): ListUsageRef[] {
  return rules.flatMap((rule, ruleIndex) => {
    if (excludeRuleIndex !== undefined && ruleIndex === excludeRuleIndex) {
      return []
    }

    if (!getListNames(rule)?.includes(listName)) {
      return []
    }

    return [{ ruleIndex, target: getTarget(rule) }]
  })
}

/**
 * Builds a `Map<listName, ListUsageRef[]>` covering every list mentioned by
 * the supplied rules in a single pass. Useful when the caller needs to look
 * up many lists in a row (e.g. once per option in a picker).
 */
export function buildListUsageByName<T>(
  rules: T[],
  getListNames: (rule: T) => string[] | undefined,
  getTarget: (rule: T) => string,
  excludeRuleIndex?: number
): Map<string, ListUsageRef[]> {
  const usageByName = new Map<string, ListUsageRef[]>()

  rules.forEach((rule, ruleIndex) => {
    if (excludeRuleIndex !== undefined && ruleIndex === excludeRuleIndex) {
      return
    }

    for (const listName of getListNames(rule) ?? []) {
      if (!listName) {
        continue
      }

      const usage = usageByName.get(listName) ?? []
      usage.push({ ruleIndex, target: getTarget(rule) })
      usageByName.set(listName, usage)
    }
  })

  return usageByName
}
