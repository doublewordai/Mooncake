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

// Secure push endpoints (secure_push.h). A receiver advertises its control
// endpoint under its segment name; every Metadata message this process sends
// whose descriptor carries that name gains a "mc_secure_p2d" member
// ({"host", "port"}), covered by the message's tag. Every authenticated
// Metadata message received records the endpoint it carries, so a sender
// finds a receiver's endpoint after fetching its descriptor, without reading
// fabric-writable memory. Only installed hooks carry endpoints: secure mode
// installs them with the data path.
void AdvertiseP2dEndpoint(const std::string &segment, const std::string &host,
                          int port);
void WithdrawP2dEndpoint(const std::string &segment);
bool LookupP2dEndpoint(const std::string &segment, std::string *host,
                       int *port);

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
