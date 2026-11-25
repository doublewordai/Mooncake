// Secure-mode framing for the transfer engine's P2P handshake, installed into
// the g_handshake_framing_hook seam in common.h.
//
//   length (8) | control_auth tag (kTagSize) | type (1) | body
//
// The tag binds the type and body, so neither can be altered or replayed.
// Old-protocol (untyped) messages are neither sent nor accepted. With the
// hook installed, segment descriptors (and their rkeys) go only to peers that
// hold the secret, and only such peers can post Connection/Notify/Probe.

#pragma once

#include <string>
#include <utility>

#include "common.h"

namespace mooncake {
namespace secure {

int WriteAuthenticatedHandshake(int fd, HandShakeRequestType type,
                                const std::string &str);
std::pair<HandShakeRequestType, std::string> ReadAuthenticatedHandshake(
    int fd);

// Called first thing in TransferMetadata's constructor. In secure mode it
// installs the framing hook (once) and refuses any metadata mode but
// P2PHANDSHAKE: a metadata store (etcd, redis, http) publishes every segment
// descriptor, rkeys included, to whoever can reach it and takes their writes.
void OnTransferMetadataCreated(const std::string &conn_string);
// Install unconditionally (OnTransferMetadataCreated, tests); remove (tests).
void InstallHandshakeAuth();
void UninstallHandshakeAuthForTesting();

}  // namespace secure
}  // namespace mooncake
