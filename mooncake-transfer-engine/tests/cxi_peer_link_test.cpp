// Tests for CxiPeerLink, the connection state of one CXI peer. No NIC needed:
// the address vector and the handshake listener are simulated.

#include "transport/cxi_transport/cxi_peer_link.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace mooncake {
namespace {

// An address vector that records inserts and removes.
struct FakeAv {
    std::mutex mu;
    std::map<uint64_t, std::string> slots;
    uint64_t next = 1;
    int inserts = 0;
    int removes = 0;

    CxiPeerLink::AddressVector ops() {
        return {[this](const std::string& addr, uint64_t& slot) {
                    std::lock_guard<std::mutex> lock(mu);
                    slot = next++;
                    slots[slot] = addr;
                    ++inserts;
                    return 0;
                },
                [this](uint64_t slot) {
                    std::lock_guard<std::mutex> lock(mu);
                    slots.erase(slot);
                    ++removes;
                }};
    }
};

// One process: its endpoint address, its link to the peer, and a handshake
// listener that serves requests one at a time, as SocketHandShakePlugin does.
struct Process {
    std::string addr;
    FakeAv av;
    std::unique_ptr<CxiPeerLink> link;

    std::mutex mu;
    std::condition_variable cv;
    struct Request {
        std::string peer_addr;
        std::promise<std::string> reply;
    };
    std::deque<std::shared_ptr<Request>> queue;
    std::atomic<int> received{0};
    bool stop = false;
    std::thread listener;

    explicit Process(std::string a) : addr(std::move(a)) {
        link = std::make_unique<CxiPeerLink>(av.ops());
        listener = std::thread([this] {
            for (;;) {
                std::shared_ptr<Request> req;
                {
                    std::unique_lock<std::mutex> lock(mu);
                    cv.wait(lock, [this] { return stop || !queue.empty(); });
                    if (stop) return;
                    req = queue.front();
                    queue.pop_front();
                }
                ++received;
                // The passive side of the handshake.
                link->accept(req->peer_addr);
                req->reply.set_value(addr);
            }
        });
    }

    ~Process() {
        {
            std::lock_guard<std::mutex> lock(mu);
            stop = true;
        }
        cv.notify_all();
        listener.join();
    }

    // Send a handshake to this process's listener; the reply future.
    std::future<std::string> handshake(const std::string& from_addr) {
        auto req = std::make_shared<Request>();
        req->peer_addr = from_addr;
        auto fut = req->reply.get_future();
        {
            std::lock_guard<std::mutex> lock(mu);
            queue.push_back(req);
        }
        cv.notify_all();
        return fut;
    }
};

constexpr auto kRpcTimeout = std::chrono::seconds(5);

// The active handshake from `self` to `peer`, bounded like the socket
// handshake's receive timeout.
std::function<int(std::string&)> Exchange(Process& self, Process& peer) {
    return [&self, &peer](std::string& peer_addr) {
        auto fut = peer.handshake(self.addr);
        if (fut.wait_for(kRpcTimeout) != std::future_status::ready) return -1;
        peer_addr = fut.get();
        return 0;
    };
}

// Two processes send to each other first at the same moment. Each one's
// handshake is in flight while the other's reaches its listener. Neither may
// wait out the RPC timeout (the 60 s stalls of DW-1288 under the socket
// handshake), and both end up connected to the other's address.
TEST(CxiPeerLinkTest, SimultaneousOpenDoesNotDeadlock) {
    Process a("addr-a"), b("addr-b");
    std::atomic<int> in_flight{0};
    auto both_in_flight = [&in_flight] {
        ++in_flight;
        while (in_flight.load() < 2) std::this_thread::yield();
    };
    auto connect = [&both_in_flight](Process& self, Process& peer) {
        auto exchange = Exchange(self, peer);
        return self.link->connect([&](std::string& peer_addr) {
            both_in_flight();
            return exchange(peer_addr);
        });
    };

    const auto t0 = std::chrono::steady_clock::now();
    auto ra = std::async(std::launch::async, [&] { return connect(a, b); });
    auto rb = std::async(std::launch::async, [&] { return connect(b, a); });
    EXPECT_EQ(0, ra.get());
    EXPECT_EQ(0, rb.get());
    EXPECT_LT(std::chrono::steady_clock::now() - t0, kRpcTimeout);

    EXPECT_TRUE(a.link->connected());
    EXPECT_TRUE(b.link->connected());
    EXPECT_EQ("addr-b", a.av.slots.at(a.link->slot()));
    EXPECT_EQ("addr-a", b.av.slots.at(b.link->slot()));
    // The crossing handshakes kept the first slot rather than replacing it.
    EXPECT_EQ(1, a.av.inserts);
    EXPECT_EQ(0, a.av.removes);
    EXPECT_EQ(1, b.av.inserts);
    EXPECT_EQ(0, b.av.removes);
}

// A repeated handshake from a peer whose address is unchanged keeps the slot,
// so transfers already posted to it are not cut off.
TEST(CxiPeerLinkTest, RepeatedPassiveHandshakeKeepsSlot) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    ASSERT_EQ(0, link.accept("addr-b"));
    const uint64_t slot = link.slot();
    ASSERT_EQ(0, link.accept("addr-b"));
    EXPECT_EQ(slot, link.slot());
    EXPECT_EQ(1, av.inserts);
    EXPECT_EQ(0, av.removes);
}

// A peer that comes back with a new endpoint address replaces the old slot.
TEST(CxiPeerLinkTest, NewPeerAddressReplacesSlot) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    ASSERT_EQ(0, link.accept("addr-b"));
    const uint64_t old_slot = link.slot();
    ASSERT_EQ(0, link.accept("addr-b2"));
    EXPECT_NE(old_slot, link.slot());
    EXPECT_EQ(0u, av.slots.count(old_slot));
    EXPECT_EQ("addr-b2", av.slots.at(link.slot()));
}

// The active RPC failed (e.g. timed out) but the peer's own handshake
// connected the link meanwhile: the link is usable.
TEST(CxiPeerLinkTest, FailedActiveAfterPassiveConnectSucceeds) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    int rc = link.connect([&link](std::string&) {
        EXPECT_EQ(0, link.accept("addr-b"));
        return -1;
    });
    EXPECT_EQ(0, rc);
    EXPECT_TRUE(link.connected());
}

TEST(CxiPeerLinkTest, FailedActiveLeavesLinkUnconnected) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    EXPECT_NE(0, link.connect([](std::string&) { return -1; }));
    EXPECT_FALSE(link.connected());
    EXPECT_NE(0, link.connect([](std::string& addr) {
        addr.clear();  // a reply without an address
        return 0;
    }));
    EXPECT_FALSE(link.connected());
}

// Senders racing to connect the same link run one handshake.
TEST(CxiPeerLinkTest, ConcurrentActiveConnectsHandshakeOnce) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    std::atomic<int> exchanges{0};
    std::vector<std::thread> senders;
    for (int i = 0; i < 8; ++i) {
        senders.emplace_back([&] {
            EXPECT_EQ(0, link.connect([&](std::string& addr) {
                ++exchanges;
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                addr = "addr-b";
                return 0;
            }));
        });
    }
    for (auto& t : senders) t.join();
    EXPECT_EQ(1, exchanges.load());
    EXPECT_EQ(1, av.inserts);
}

TEST(CxiPeerLinkTest, DisconnectRemovesSlot) {
    FakeAv av;
    CxiPeerLink link(av.ops());
    ASSERT_EQ(0, link.accept("addr-b"));
    link.disconnect();
    EXPECT_FALSE(link.connected());
    EXPECT_EQ(1, av.removes);
    EXPECT_TRUE(av.slots.empty());
    // Forgetting (teardown) leaves the address vector alone.
    ASSERT_EQ(0, link.accept("addr-b"));
    link.forget();
    EXPECT_FALSE(link.connected());
    EXPECT_EQ(1, av.removes);
}

}  // namespace
}  // namespace mooncake
