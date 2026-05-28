#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

// Registers the auto-heal endpoints:
//   GET  /api/autoheal          - current auto-heal settings + the auto list's domains
//   POST /api/autoheal/promote  - append domains to the auto list and guarantee a
//                                 top-priority route rule for it, then STAGE the
//                                 resulting config (same path as POST /api/config).
void register_autoheal_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
