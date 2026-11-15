#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <sys/types.h>

#include <ylt/util/tl/expected.hpp>

namespace mooncake {

// Socket names that start with '/' are bound as filesystem Unix sockets at
// that path. Any other name is bound in the abstract namespace, which is
// scoped to the network namespace of the process.
bool isFilesystemUdsPath(const std::string &socket_name);

// Lightweight Unix domain socket helper for one-shot, performance-insensitive
// control-plane exchanges such as local fd passing. This opens short-lived
// blocking sockets and handles one connection at a time; use asio-based
// transport instead for latency-sensitive, high-throughput, or long-lived I/O.
class UdsConnection {
   public:
    UdsConnection() = default;
    explicit UdsConnection(int fd);
    ~UdsConnection();

    UdsConnection(const UdsConnection &) = delete;
    UdsConnection &operator=(const UdsConnection &) = delete;

    UdsConnection(UdsConnection &&other) noexcept;
    UdsConnection &operator=(UdsConnection &&other) noexcept;

    bool valid() const;
    int fd() const;
    int release();
    void close();
    tl::expected<void, std::string> setRecvTimeout(
        std::chrono::seconds timeout);

    int sendRaw(const void *data, size_t len);
    int recvRaw(void *data, size_t len);
    int sendFd(int fd, void *data, size_t data_len);
    int recvFd(void *data, size_t data_len);

   private:
    int fd_ = -1;
};

class UdsConnector {
   public:
    explicit UdsConnector(
        std::string socket_name,
        std::chrono::milliseconds connect_timeout = std::chrono::seconds(5));
    tl::expected<std::unique_ptr<UdsConnection>, std::string> connect();

   private:
    std::string socket_name_;
    std::chrono::milliseconds connect_timeout_;
};

class UdsAcceptor {
   public:
    using Handler = std::function<void(UdsConnection &)>;

    // socket_mode is applied with chmod() to filesystem sockets only.
    explicit UdsAcceptor(std::string socket_name, mode_t socket_mode = 0660);
    ~UdsAcceptor();

    void registerHandler(Handler handler);
    tl::expected<void, std::string> start();
    void stop();

   private:
    void acceptLoop();
    void wakeAccept();
    void unlinkBoundSocketFile();

    std::string socket_name_;
    mode_t socket_mode_;
    // Identity of the socket file this acceptor created, so stop() never
    // unlinks a file that another process has since bound at the same path.
    bool bound_socket_file_ = false;
    dev_t bound_dev_ = 0;
    ino_t bound_ino_ = 0;
    Handler handler_;
    int listen_fd_ = -1;
    std::atomic<int> active_client_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace mooncake
