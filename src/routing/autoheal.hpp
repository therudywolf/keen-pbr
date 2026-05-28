#pragma once

#include <string>
#include <vector>

#include "../config/config.hpp"

namespace keen_pbr3 {

// Auto-heal: promote a set of "leaking" domains to a top-priority VPN list.
// =========================================================================
// This generalizes the manual OpenAI fix — placing a route rule
// {list:[auto], outbound:VPN} FIRST so the auto list's domains win over every
// other rule. The mechanism is one-shot and purely declarative: it transforms a
// config value, it does not touch the kernel, run a worker, or re-apply routing
// by itself. The API handler feeds the result back through the normal config
// staging path, so routing only changes once the staged config is applied.
//
// promote_domains takes the current config by value and returns a NEW config
// that:
//   1. has a list named `list` (created with empty domains/ip_cidrs if absent);
//   2. has `domains` appended to that list, de-duplicated against the entries
//      already present in the list (insertion order of genuinely new domains is
//      preserved; nothing already in the list is added again);
//   3. has a route rule {enabled:true, list:[list], outbound:outbound} as its
//      first rule (route.rules[0]). If rules[0] is already exactly that rule it
//      is reused as-is; otherwise the rule is inserted at the front. The list
//      may also appear in other rules — that is left untouched; only the
//      top-priority rule is guaranteed. No other rule's `list`/`outbound` is
//      modified, and rule ordering is otherwise preserved.
// Everything else in the config is carried through unchanged.
//
// `domains` entries that are empty strings are ignored. Calling promote_domains
// again with the same arguments is idempotent: no duplicate list entries and no
// duplicate top rule are produced.
//
// `Config` is the keen-pbr alias for api::ConfigObject (see config.hpp).
Config promote_domains(Config cfg,
                       const std::string& list,
                       const std::string& outbound,
                       const std::vector<std::string>& domains);

}  // namespace keen_pbr3
