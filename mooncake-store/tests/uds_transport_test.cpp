#include "uds_transport.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <string>
#include <thread>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace mooncake {
namespace {

std::string testSocketPath(const std::string &suffix) {
    return "uds_transport_test_" + std::to_string(getpid()) + "_" + suffix;
}

int createTempFd(const char *content) {
    char path[] = "/tmp/uds_transport_test_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    unlink(path);
    if (write(fd, content, strlen(content)) < 0) {
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

std::string readFdContent(int fd) {
    char buffer[64] = {};
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n < 0) return "";
    return std::string(buffer, static_cast<size_t>(n));
}

bool waitForFlag(const std::atomic<bool> &flag) {
    for (int i = 0; i < 100; ++i) {
        if (flag.load()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return flag.load();
}

// Creates a private directory for filesystem socket tests and removes it,
// along with any socket the test left behind, on destruction.
class TempSocketDir {
   public:
    TempSocketDir() {
        char path[] = "/tmp/uds_fs_test_XXXXXX";
        if (mkdtemp(path) != nullptr) dir_ = path;
    }
    ~TempSocketDir() {
        if (dir_.empty()) return;
        unlink(path("sock").c_str());
        rmdir(dir_.c_str());
    }
    bool valid() const { return !dir_.empty(); }
    std::string path(const std::string &name) const {
        return dir_ + "/" + name;
    }

   private:
    std::string dir_;
};

bool isSocketFile(const std::string &path) {
    struct stat st;
    return lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
}

}  // namespace

TEST(UdsTransportTest, SendsRawPayload) {
    UdsAcceptor acceptor(testSocketPath("raw"));
    std::atomic<bool> handled{false};

    acceptor.registerHandler([&](UdsConnection &connection) {
        uint32_t value = 0;
        EXPECT_EQ(connection.recvRaw(&value, sizeof(value)), 0);
        value += 1;
        EXPECT_EQ(connection.sendRaw(&value, sizeof(value)), 0);
        handled = true;
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(testSocketPath("raw"));
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    uint32_t value = 41;
    ASSERT_EQ(connection->sendRaw(&value, sizeof(value)), 0);
    ASSERT_EQ(connection->recvRaw(&value, sizeof(value)), 0);
    EXPECT_EQ(value, 42);

    acceptor.stop();
    EXPECT_TRUE(handled.load());
}

TEST(UdsTransportTest, SendsFdFromClientToServer) {
    UdsAcceptor acceptor(testSocketPath("client_fd"));
    std::atomic<bool> received{false};

    acceptor.registerHandler([&](UdsConnection &connection) {
        uint32_t marker = 0;
        int fd = connection.recvFd(&marker, sizeof(marker));
        ASSERT_GE(fd, 0);
        EXPECT_EQ(marker, 7u);
        EXPECT_EQ(readFdContent(fd), "client-to-server");
        close(fd);
        received = true;
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(testSocketPath("client_fd"));
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    int fd = createTempFd("client-to-server");
    ASSERT_GE(fd, 0);
    uint32_t marker = 7;
    ASSERT_EQ(connection->sendFd(fd, &marker, sizeof(marker)), 0);
    close(fd);

    ASSERT_TRUE(waitForFlag(received));
    acceptor.stop();
    EXPECT_TRUE(received.load());
}

TEST(UdsTransportTest, RejectsFdWithPartialPayload) {
    int sockets[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets), 0);

    UdsConnection receiver(sockets[1]);
    int fd = createTempFd("partial-payload");
    ASSERT_GE(fd, 0);

    uint32_t marker = 7;
    iovec iov;
    iov.iov_base = &marker;
    iov.iov_len = sizeof(marker) - 1;

    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));

    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ASSERT_EQ(sendmsg(sockets[0], &msg, 0),
              static_cast<ssize_t>(sizeof(marker) - 1));
    close(fd);
    close(sockets[0]);

    uint32_t received_marker = 0;
    EXPECT_LT(receiver.recvFd(&received_marker, sizeof(received_marker)), 0);
}

TEST(UdsTransportTest, SendsFdFromServerToClient) {
    UdsAcceptor acceptor(testSocketPath("server_fd"));

    acceptor.registerHandler([&](UdsConnection &connection) {
        int fd = createTempFd("server-to-client");
        ASSERT_GE(fd, 0);
        uint32_t marker = 9;
        EXPECT_EQ(connection.sendFd(fd, &marker, sizeof(marker)), 0);
        close(fd);
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(testSocketPath("server_fd"));
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    uint32_t marker = 0;
    int fd = connection->recvFd(&marker, sizeof(marker));
    ASSERT_GE(fd, 0);
    EXPECT_EQ(marker, 9u);
    EXPECT_EQ(readFdContent(fd), "server-to-client");
    close(fd);

    acceptor.stop();
}

TEST(UdsTransportTest, StopWakesAcceptLoop) {
    UdsAcceptor acceptor(testSocketPath("stop"));
    acceptor.registerHandler([](UdsConnection &) {});
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();
    acceptor.stop();

    UdsConnector connector(testSocketPath("stop"));
    EXPECT_FALSE(connector.connect());
}

TEST(UdsTransportTest, StopWakesActiveClientHandler) {
    UdsAcceptor acceptor(testSocketPath("active_stop"));
    std::atomic<bool> entered{false};
    std::atomic<bool> exited{false};

    acceptor.registerHandler([&](UdsConnection &connection) {
        entered = true;
        uint32_t value = 0;
        EXPECT_EQ(connection.recvRaw(&value, sizeof(value)), -1);
        exited = true;
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(testSocketPath("active_stop"));
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();

    ASSERT_TRUE(waitForFlag(entered));
    acceptor.stop();
    EXPECT_TRUE(exited.load());
}

TEST(UdsTransportTest, ConnectRejectsNonPositiveTimeout) {
    UdsConnector connector(testSocketPath("invalid_timeout"),
                           std::chrono::milliseconds(0));
    auto connection_result = connector.connect();
    ASSERT_FALSE(connection_result);
    EXPECT_NE(connection_result.error().find("timeout"), std::string::npos);
}

TEST(UdsTransportTest, ConnectFailureReturnsPromptlyWithShortTimeout) {
    std::string socket_name = testSocketPath("missing");
    UdsConnector connector(socket_name, std::chrono::milliseconds(10));

    auto start = std::chrono::steady_clock::now();
    auto connection_result = connector.connect();
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_FALSE(connection_result);
    EXPECT_LT(elapsed, std::chrono::seconds(1));
    EXPECT_NE(connection_result.error().find(socket_name), std::string::npos);
}

TEST(UdsTransportTest, ConnectClearsSendTimeout) {
    UdsAcceptor acceptor(testSocketPath("send_timeout"));
    acceptor.registerHandler([](UdsConnection &) {});
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(testSocketPath("send_timeout"),
                           std::chrono::milliseconds(10));
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    timeval tv;
    socklen_t tv_len = sizeof(tv);
    ASSERT_EQ(
        getsockopt(connection->fd(), SOL_SOCKET, SO_SNDTIMEO, &tv, &tv_len), 0);
    EXPECT_EQ(tv.tv_sec, 0);
    EXPECT_EQ(tv.tv_usec, 0);

    acceptor.stop();
}

TEST(UdsTransportTest, StartRequiresRegisteredHandler) {
    UdsAcceptor acceptor(testSocketPath("no_handler"));
    auto start_result = acceptor.start();
    ASSERT_FALSE(start_result);
    EXPECT_NE(start_result.error().find("handler"), std::string::npos);
}

TEST(UdsTransportTest, IsFilesystemUdsPath) {
    EXPECT_TRUE(isFilesystemUdsPath("/run/mooncake/client.sock"));
    EXPECT_FALSE(isFilesystemUdsPath("@mooncake_client_50052.sock"));
    EXPECT_FALSE(isFilesystemUdsPath("relative.sock"));
    EXPECT_FALSE(isFilesystemUdsPath(""));
}

TEST(UdsTransportTest, FilesystemSocketAcceptAndConnect) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");

    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([](UdsConnection &connection) {
        uint32_t value = 0;
        EXPECT_EQ(connection.recvRaw(&value, sizeof(value)), 0);
        value += 1;
        EXPECT_EQ(connection.sendRaw(&value, sizeof(value)), 0);
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();
    EXPECT_TRUE(isSocketFile(socket_path));

    UdsConnector connector(socket_path);
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    uint32_t value = 41;
    ASSERT_EQ(connection->sendRaw(&value, sizeof(value)), 0);
    ASSERT_EQ(connection->recvRaw(&value, sizeof(value)), 0);
    EXPECT_EQ(value, 42u);

    acceptor.stop();
    // The acceptor removes the socket file it created.
    EXPECT_FALSE(isSocketFile(socket_path));
    EXPECT_FALSE(UdsConnector(socket_path).connect());
}

TEST(UdsTransportTest, FilesystemSocketPassesMemfd) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");
    constexpr size_t kSize = 4096;
    const char kMessage[] = "written-by-client";
    const char kReply[] = "written-by-server";
    std::atomic<bool> verified{false};

    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([&](UdsConnection &connection) {
        uint32_t marker = 0;
        int fd = connection.recvFd(&marker, sizeof(marker));
        ASSERT_GE(fd, 0);
        EXPECT_EQ(marker, 11u);
        void *mapping = mmap(nullptr, kSize, PROT_READ | PROT_WRITE, MAP_SHARED,
                             fd, /*offset=*/0);
        close(fd);
        ASSERT_NE(mapping, MAP_FAILED);
        EXPECT_EQ(std::string(static_cast<const char *>(mapping)), kMessage);
        memcpy(mapping, kReply, sizeof(kReply));
        munmap(mapping, kSize);
        verified = true;
        uint8_t ack = 1;
        EXPECT_EQ(connection.sendRaw(&ack, sizeof(ack)), 0);
    });
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    int memfd = memfd_create("uds_transport_test", MFD_CLOEXEC);
    ASSERT_GE(memfd, 0);
    ASSERT_EQ(ftruncate(memfd, kSize), 0);
    void *mapping =
        mmap(nullptr, kSize, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    ASSERT_NE(mapping, MAP_FAILED);

    memcpy(mapping, kMessage, sizeof(kMessage));

    UdsConnector connector(socket_path);
    auto connection_result = connector.connect();
    ASSERT_TRUE(connection_result) << connection_result.error();
    auto connection = std::move(connection_result.value());

    uint32_t marker = 11;
    ASSERT_EQ(connection->sendFd(memfd, &marker, sizeof(marker)), 0);
    close(memfd);

    // The server read our write through its own mapping and replied through
    // it; the reply must be visible through ours.
    uint8_t ack = 0;
    ASSERT_EQ(connection->recvRaw(&ack, sizeof(ack)), 0);
    EXPECT_EQ(ack, 1);
    EXPECT_TRUE(verified.load());
    EXPECT_EQ(std::string(static_cast<const char *>(mapping)), kReply);
    munmap(mapping, kSize);
    acceptor.stop();
}

TEST(UdsTransportTest, FilesystemSocketReplacesStaleSocketFile) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");

    // Leave a bound socket file behind with no listener, as a crashed
    // process would.
    int stale_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(stale_fd, 0);
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(bind(stale_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)),
              0);
    close(stale_fd);
    ASSERT_TRUE(isSocketFile(socket_path));

    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([](UdsConnection &) {});
    auto start_result = acceptor.start();
    ASSERT_TRUE(start_result) << start_result.error();

    UdsConnector connector(socket_path);
    auto connection_result = connector.connect();
    EXPECT_TRUE(connection_result) << connection_result.error();
    acceptor.stop();
}

TEST(UdsTransportTest, FilesystemSocketRefusesLiveListener) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");

    UdsAcceptor first(socket_path);
    first.registerHandler([](UdsConnection &) {});
    auto first_result = first.start();
    ASSERT_TRUE(first_result) << first_result.error();

    UdsAcceptor second(socket_path);
    second.registerHandler([](UdsConnection &) {});
    auto second_result = second.start();
    ASSERT_FALSE(second_result);
    EXPECT_NE(second_result.error().find("in use"), std::string::npos);

    // The first listener still owns the path.
    EXPECT_TRUE(UdsConnector(socket_path).connect());
    first.stop();
}

TEST(UdsTransportTest, FilesystemSocketRefusesToUnlinkRegularFile) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");

    int fd = open(socket_path.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(write(fd, "keep", 4), 4);
    close(fd);

    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([](UdsConnection &) {});
    auto start_result = acceptor.start();
    ASSERT_FALSE(start_result);
    EXPECT_NE(start_result.error().find("non-socket"), std::string::npos);

    struct stat st;
    ASSERT_EQ(lstat(socket_path.c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_size, 4);
}

TEST(UdsTransportTest, FilesystemSocketRefusesToUnlinkDirectory) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());
    const std::string socket_path = dir.path("sock");
    ASSERT_EQ(mkdir(socket_path.c_str(), 0700), 0);

    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([](UdsConnection &) {});
    EXPECT_FALSE(acceptor.start());

    struct stat st;
    ASSERT_EQ(lstat(socket_path.c_str(), &st), 0);
    EXPECT_TRUE(S_ISDIR(st.st_mode));
    rmdir(socket_path.c_str());
}

TEST(UdsTransportTest, FilesystemSocketAppliesMode) {
    TempSocketDir dir;
    ASSERT_TRUE(dir.valid());

    for (mode_t mode : {static_cast<mode_t>(0660), static_cast<mode_t>(0600),
                        static_cast<mode_t>(0666)}) {
        const std::string socket_path = dir.path("sock");
        UdsAcceptor acceptor(socket_path, mode);
        acceptor.registerHandler([](UdsConnection &) {});
        auto start_result = acceptor.start();
        ASSERT_TRUE(start_result) << start_result.error();

        struct stat st;
        ASSERT_EQ(lstat(socket_path.c_str(), &st), 0);
        EXPECT_TRUE(S_ISSOCK(st.st_mode));
        EXPECT_EQ(st.st_mode & 07777, mode);
        acceptor.stop();
    }
}

TEST(UdsTransportTest, FilesystemSocketRejectsTooLongPath) {
    std::string socket_path =
        "/" + std::string(sizeof(sockaddr_un{}.sun_path), 'x');
    UdsAcceptor acceptor(socket_path);
    acceptor.registerHandler([](UdsConnection &) {});
    auto start_result = acceptor.start();
    ASSERT_FALSE(start_result);
    EXPECT_NE(start_result.error().find("too long"), std::string::npos);

    auto connection_result = UdsConnector(socket_path).connect();
    ASSERT_FALSE(connection_result);
    EXPECT_NE(connection_result.error().find("too long"), std::string::npos);
}

}  // namespace mooncake
