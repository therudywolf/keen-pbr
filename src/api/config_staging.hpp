#pragma once

#ifdef WITH_API

// serialize_config_pretty now lives in the (unguarded) shared config writer so
// the daemon's auto-heal worker can reuse it too. This header is kept as a
// stable include point for the existing API handlers.
#include "../config/config_writer.hpp"

#endif  // WITH_API
