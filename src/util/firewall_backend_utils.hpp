#pragma once

#include "../firewall/firewall.hpp"

namespace keen_pbr3 {

// Cached: positive answers for the process lifetime, negative ones for about
// a minute (see CachedProbe).
bool firewall_backend_command_exists(FirewallBackend backend);
FirewallBackend detect_firewall_backend();
FirewallBackend resolve_firewall_backend(FirewallBackendPreference backend_pref);

#ifdef KEEN_PBR3_TESTING
void reset_firewall_backend_probe_cache_for_tests();
#endif

} // namespace keen_pbr3
