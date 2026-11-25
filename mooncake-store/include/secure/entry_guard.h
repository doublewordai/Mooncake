// Copyright 2026 Doubleword AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Store entry points that do not go through the sealing decorator
// (SecurePyClient) refuse to operate in secure mode. Built only with
// WITH_SECURE_KV.
//
// A RealClient used directly stores whatever it is handed, so a put through
// it would put plaintext into a store segment. In secure mode a RealClient
// may only be set up by SecurePyClient (inside its
// CiphertextRegistrationScope); every other entry point -- the C API and the
// Rust and Go bindings over it, the standalone client process
// (mooncake_client) -- is refused.

#pragma once

#include <glog/logging.h>

#include "secure/kv_crypto.h"
#include "secure/secure_transport.h"

namespace mooncake {
namespace secure {

// True (and logs why) in secure mode: `what` is an entry point that never
// seals, and must not start.
inline bool RefuseUnsealedEntryPoint(const char *what) {
    if (!SecureModeEnabled()) return false;
    LOG(ERROR) << "Secure mode (MC_SECURE_MODE) refuses " << what
               << ": it does not seal store values; use the Python store "
                  "client (MooncakeDistributedStore), which does";
    return true;
}

// True (and logs why) in secure mode unless the caller is SecurePyClient
// setting up its inner client: RealClient setup outside the decorator.
inline bool RefuseUnsealedClientSetup() {
    if (!SecureModeEnabled() || CiphertextRegistrationScope::Active())
        return false;
    LOG(ERROR) << "Secure mode (MC_SECURE_MODE) refuses to set up a store "
                  "client outside the sealing decorator: values put through "
                  "it would be stored in plaintext";
    return true;
}

}  // namespace secure
}  // namespace mooncake
