// Fail closed when secure mode (DW-1288) is asked of a binary built without
// it: a build without -DWITH_SECURE_KV=ON would otherwise ignore the switch
// and run in plaintext. Included by the TUs every Mooncake process links
// (TransferEngine, the master); the check runs once, at load.
#pragma once

#ifndef WITH_SECURE_KV
#include <strings.h>

#include <cstdio>
#include <cstdlib>
#include <initializer_list>

namespace mooncake {
namespace secure_mode_guard {

inline const bool kChecked = [] {
    for (const char* name : {"MC_SECURE_MODE", "MC_CONTROL_AUTH"}) {
        const char* v = std::getenv(name);
        if (!v || !*v || !strcasecmp(v, "0") || !strcasecmp(v, "false") ||
            !strcasecmp(v, "off") || !strcasecmp(v, "no"))
            continue;
        std::fprintf(stderr,
                     "Mooncake: %s=%s asks for secure mode, but this binary "
                     "was built without WITH_SECURE_KV; refusing to start. "
                     "Use a -DWITH_SECURE_KV=ON build, or unset %s.\n",
                     name, v, name);
        std::_Exit(78);  // EX_CONFIG
    }
    return true;
}();

}  // namespace secure_mode_guard
}  // namespace mooncake
#endif  // WITH_SECURE_KV
