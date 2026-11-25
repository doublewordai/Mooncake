// The P2P handshake in secure mode: framing guards over a socketpair, and the
// real handshake daemon over TCP refusing unauthenticated, wrongly keyed and
// replayed requests without ever running its handler.

#include "handshake_auth.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include "common.h"
#include "control_auth.h"
#include "transfer_metadata.h"
#include "transfer_metadata_plugin.h"

namespace mooncake {
namespace secure {
namespace {

namespace ca = control_auth;

const std::string kSecretA(40, 'a');
const std::string kSecretB(40, 'b');

int64_t NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// The bytes WriteAuthenticatedHandshake puts on the wire.
std::string Frame(HandShakeRequestType type, const std::string &body) {
    int fds[2];
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    EXPECT_EQ(WriteAuthenticatedHandshake(fds[0], type, body), 0);
    close(fds[0]);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = read(fds[1], buf, sizeof(buf))) > 0) out.append(buf, n);
    close(fds[1]);
    return out;
}

// An upstream (unauthenticated) typed frame.
std::string PlainFrame(HandShakeRequestType type, const std::string &body) {
    uint64_t length = body.size() + 1;
    std::string out(reinterpret_cast<const char *>(&length), sizeof(length));
    out.push_back(static_cast<char>(type));
    out.append(body);
    return out;
}

// A frame whose tag carries a chosen timestamp.
std::string FrameAt(HandShakeRequestType type, const std::string &body,
                    int64_t ts_ms) {
    std::string bound(1, static_cast<char>(type));
    bound += body;
    std::string tag =
        ca::MakeTagAtForTesting(ca::Domain::kHandshake, bound, ts_ms);
    uint64_t length = tag.size() + bound.size();
    std::string out(reinterpret_cast<const char *>(&length), sizeof(length));
    return out + tag + bound;
}

std::pair<HandShakeRequestType, std::string> ReadFrom(const std::string &wire) {
    int fds[2];
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    EXPECT_EQ(write(fds[0], wire.data(), wire.size()),
              static_cast<ssize_t>(wire.size()));
    close(fds[0]);
    auto result = readString(fds[1]);  // through the installed hook
    close(fds[1]);
    return result;
}

class HandshakeAuthTest : public ::testing::Test {
   protected:
    void SetUp() override {
        ca::ConfigureForTesting(true, kSecretA);
        InstallHandshakeAuth();
    }
    void TearDown() override {
        UninstallHandshakeAuthForTesting();
        ca::ResetForTesting();
    }
};

TEST_F(HandshakeAuthTest, AuthenticatedFrameRoundTrips) {
    auto [type, body] =
        ReadFrom(Frame(HandShakeRequestType::Metadata, "{\"a\":1}"));
    EXPECT_EQ(type, HandShakeRequestType::Metadata);
    EXPECT_EQ(body, "{\"a\":1}");
}

TEST_F(HandshakeAuthTest, WriteStringGoesThroughTheHook) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    ASSERT_EQ(writeString(fds[0], HandShakeRequestType::Probe, "{}"), 0);
    auto [type, body] = readString(fds[1]);
    EXPECT_EQ(type, HandShakeRequestType::Probe);
    EXPECT_EQ(body, "{}");
    close(fds[0]);
    close(fds[1]);
}

TEST_F(HandshakeAuthTest, UnauthenticatedFrameIsRefused) {
    auto [type, body] =
        ReadFrom(PlainFrame(HandShakeRequestType::Metadata, "{\"a\":1}"));
    EXPECT_EQ(type, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, WrongKeyIsRefused) {
    auto wire = Frame(HandShakeRequestType::Metadata, "{}");
    ca::ConfigureForTesting(true, kSecretB);
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, AlteredBodyIsRefused) {
    auto wire = Frame(HandShakeRequestType::Metadata, "{\"a\":1}");
    wire[wire.size() - 2] = '2';
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, AlteredTypeIsRefused) {
    auto wire = Frame(HandShakeRequestType::Probe, "{}");
    wire[sizeof(uint64_t) + ca::kTagSize] =
        static_cast<char>(HandShakeRequestType::Connection);
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, ReplayedFrameIsRefused) {
    auto wire = Frame(HandShakeRequestType::Metadata, "{}");
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Metadata);
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, StaleFrameIsRefused) {
    ca::ConfigureForTesting(true, kSecretA, /*max_skew_ms=*/5000);
    auto wire = FrameAt(HandShakeRequestType::Metadata, "{}", NowMs() - 6000);
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, OldProtocolIsRefused) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    EXPECT_NE(writeString(fds[0], HandShakeRequestType::OldProtocol, "{}"), 0);
    close(fds[0]);
    close(fds[1]);
    uint64_t length = 2;
    std::string wire(reinterpret_cast<const char *>(&length), sizeof(length));
    wire += "{}";
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, NoKeyFailsClosedBothWays) {
    auto wire = Frame(HandShakeRequestType::Metadata, "{}");
    ca::ConfigureForTesting(true, "");
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    EXPECT_NE(writeString(fds[0], HandShakeRequestType::Metadata, "{}"), 0);
    close(fds[0]);
    close(fds[1]);
    EXPECT_EQ(ReadFrom(wire).first, HandShakeRequestType::Invalid);
}

TEST_F(HandshakeAuthTest, SecureModeRefusesMetadataStores) {
    EXPECT_DEATH(OnTransferMetadataCreated("etcd://127.0.0.1:2379"),
                 "P2PHANDSHAKE");
    EXPECT_DEATH(OnTransferMetadataCreated("http://127.0.0.1:8080/metadata"),
                 "P2PHANDSHAKE");
}

// The real daemon over TCP.
class HandshakeDaemonTest : public HandshakeAuthTest {
   protected:
    void SetUp() override {
        HandshakeAuthTest::SetUp();
        server_ = HandShakePlugin::Create(P2PHANDSHAKE);
        server_->registerOnMetadataCallBack(
            [this](const Json::Value &, Json::Value &local) {
                ++served_;
                local["rkey"] = "secret-rkey";
                return 0;
            });
        // The daemon binds the port itself so that its accept loop has a
        // timeout and the destructor can stop it.
        int sockfd = -1;
        port_ = findAvailableTcpPort(sockfd);
        ASSERT_GT(port_, 0);
        close(sockfd);
        ASSERT_EQ(server_->startDaemon(port_, -1), 0);
    }
    void TearDown() override {
        server_.reset();
        HandshakeAuthTest::TearDown();
    }

    // Sends raw bytes and returns everything the daemon answers.
    std::string RawExchange(const std::string &wire) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        EXPECT_EQ(connect(fd, (sockaddr *)&addr, sizeof(addr)), 0);
        EXPECT_EQ(write(fd, wire.data(), wire.size()),
                  static_cast<ssize_t>(wire.size()));
        std::string out;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) out.append(buf, n);
        close(fd);
        return out;
    }

    std::shared_ptr<HandShakePlugin> server_;
    uint16_t port_ = 0;
    std::atomic<int> served_{0};
};

TEST_F(HandshakeDaemonTest, AuthenticatedPeerGetsMetadata) {
    auto client = HandShakePlugin::Create(P2PHANDSHAKE);
    Json::Value local, peer;
    local["name"] = "client";
    ASSERT_EQ(client->exchangeMetadata("127.0.0.1", port_, local, peer), 0);
    EXPECT_EQ(peer["rkey"].asString(), "secret-rkey");
    EXPECT_EQ(served_.load(), 1);
}

TEST_F(HandshakeDaemonTest, UnauthenticatedPeerGetsNothing) {
    auto answer =
        RawExchange(PlainFrame(HandShakeRequestType::Metadata, "{}"));
    EXPECT_EQ(answer.find("secret-rkey"), std::string::npos);
    EXPECT_TRUE(answer.empty());
    EXPECT_EQ(served_.load(), 0);
}

TEST_F(HandshakeDaemonTest, WrongKeyPeerGetsNothing) {
    ca::ConfigureForTesting(true, kSecretB);
    auto wire = Frame(HandShakeRequestType::Metadata, "{}");
    ca::ConfigureForTesting(true, kSecretA);
    EXPECT_TRUE(RawExchange(wire).empty());
    EXPECT_EQ(served_.load(), 0);
}

TEST_F(HandshakeDaemonTest, ReplayedRequestGetsNothing) {
    auto wire = Frame(HandShakeRequestType::Metadata, "{}");
    EXPECT_NE(RawExchange(wire).find("secret-rkey"), std::string::npos);
    EXPECT_EQ(served_.load(), 1);
    EXPECT_TRUE(RawExchange(wire).empty());
    EXPECT_EQ(served_.load(), 1);
}

TEST_F(HandshakeDaemonTest, StaleRequestGetsNothing) {
    ca::ConfigureForTesting(true, kSecretA, /*max_skew_ms=*/5000);
    EXPECT_TRUE(
        RawExchange(FrameAt(HandShakeRequestType::Metadata, "{}",
                            NowMs() - 6000))
            .empty());
    EXPECT_EQ(served_.load(), 0);
}

TEST_F(HandshakeDaemonTest, ClientRefusesAnUnauthenticatedServer) {
    // A server without the hook (an impostor on the fabric) answers in
    // upstream framing; the secure client must not accept its descriptor.
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(listen_fd, (sockaddr *)&addr, sizeof(addr)), 0);
    socklen_t len = sizeof(addr);
    getsockname(listen_fd, (sockaddr *)&addr, &len);
    ASSERT_EQ(listen(listen_fd, 1), 0);
    std::thread impostor([&] {
        int fd = accept(listen_fd, nullptr, nullptr);
        char buf[8192];
        (void)!read(fd, buf, sizeof(buf));
        auto wire =
            PlainFrame(HandShakeRequestType::Metadata, "{\"rkey\":\"forged\"}");
        (void)!write(fd, wire.data(), wire.size());
        shutdown(fd, SHUT_WR);
        (void)!read(fd, buf, sizeof(buf));
        close(fd);
    });
    auto client = HandShakePlugin::Create(P2PHANDSHAKE);
    Json::Value local, peer;
    local["name"] = "client";
    EXPECT_NE(client->exchangeMetadata("127.0.0.1", ntohs(addr.sin_port),
                                       local, peer),
              0);
    EXPECT_NE(peer["rkey"].asString(), "forged");
    impostor.join();
    close(listen_fd);
}

}  // namespace
}  // namespace secure
}  // namespace mooncake
