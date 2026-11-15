#include "uds_transport.h"

#include <glog/logging.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace mooncake {
namespace {

std::string errnoMessage(const std::string &operation) {
    return operation + ": " + strerror(errno);
}

int createCloexecUdsSocket() {
#ifdef SOCK_CLOEXEC
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    // SOCK_CLOEXEC is Linux-specific; set FD_CLOEXEC after creation instead.
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
#endif
}

tl::expected<void, std::string> makeAbstractAddress(
    const std::string &socket_name, sockaddr_un &addr, socklen_t &addr_len) {
    if (socket_name.size() > sizeof(addr.sun_path) - 2) {
        return tl::make_unexpected("UDS socket name too long: " + socket_name);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, socket_name.c_str(), sizeof(addr.sun_path) - 2);
    addr_len = sizeof(sa_family_t) + 1 + socket_name.length();
    return {};
}

tl::expected<void, std::string> makeFilesystemAddress(
    const std::string &socket_path, sockaddr_un &addr, socklen_t &addr_len) {
    // sun_path must hold the path plus its NUL terminator.
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        return tl::make_unexpected("UDS socket path too long: " + socket_path);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path.c_str(), socket_path.size() + 1);
    addr_len = offsetof(sockaddr_un, sun_path) + socket_path.size() + 1;
    return {};
}

tl::expected<void, std::string> makeAddress(const std::string &socket_name,
                                            sockaddr_un &addr,
                                            socklen_t &addr_len) {
    if (isFilesystemUdsPath(socket_name)) {
        return makeFilesystemAddress(socket_name, addr, addr_len);
    }
    return makeAbstractAddress(socket_name, addr, addr_len);
}

tl::expected<void, std::string> setSendTimeout(
    int fd, std::chrono::milliseconds timeout) {
    timeval tv = {
        .tv_sec = static_cast<decltype(tv.tv_sec)>(
            std::chrono::duration_cast<std::chrono::seconds>(timeout).count()),
        .tv_usec = static_cast<decltype(tv.tv_usec)>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                timeout % std::chrono::seconds(1))
                .count()),
    };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return tl::make_unexpected(
            errnoMessage("Failed to set UDS send timeout"));
    }
    return {};
}

tl::expected<int, std::string> createConnectedSocket(
    const std::string &socket_name, std::chrono::milliseconds connect_timeout) {
    if (connect_timeout.count() <= 0) {
        return tl::make_unexpected("UDS connect timeout must be positive");
    }

    int sock_fd = createCloexecUdsSocket();
    if (sock_fd < 0) {
        return tl::make_unexpected(errnoMessage("Failed to create UDS socket"));
    }

    sockaddr_un addr;
    socklen_t addr_len = 0;
    auto addr_result = makeAddress(socket_name, addr, addr_len);
    if (!addr_result) {
        close(sock_fd);
        return tl::make_unexpected(addr_result.error());
    }

    auto timeout_result = setSendTimeout(sock_fd, connect_timeout);
    if (!timeout_result) {
        close(sock_fd);
        return tl::make_unexpected(timeout_result.error());
    }

    if (::connect(sock_fd, reinterpret_cast<sockaddr *>(&addr), addr_len) < 0) {
        auto error =
            errno == EAGAIN || errno == EINPROGRESS
                ? "Timed out connecting UDS socket '" + socket_name + "'"
                : errnoMessage("Failed to connect UDS socket '" + socket_name +
                               "'");
        close(sock_fd);
        return tl::make_unexpected(error);
    }

    auto clear_timeout_result =
        setSendTimeout(sock_fd, std::chrono::milliseconds(0));
    if (!clear_timeout_result) {
        close(sock_fd);
        return tl::make_unexpected(clear_timeout_result.error());
    }

    return sock_fd;
}

// Removes a leftover socket file from a previous run so bind() can succeed.
// Only socket files are removed, and only when nothing is listening on them.
tl::expected<void, std::string> removeStaleSocketFile(
    const std::string &socket_path) {
    struct stat st;
    if (lstat(socket_path.c_str(), &st) < 0) {
        if (errno == ENOENT) return {};
        return tl::make_unexpected(errnoMessage(
            "Failed to stat UDS socket path '" + socket_path + "'"));
    }
    if (!S_ISSOCK(st.st_mode)) {
        return tl::make_unexpected(
            "Refusing to replace non-socket file at "
            "UDS socket path '" +
            socket_path + "'");
    }

    auto probe = createConnectedSocket(socket_path, std::chrono::seconds(1));
    if (probe) {
        close(*probe);
        return tl::make_unexpected("UDS socket path '" + socket_path +
                                   "' is in use by another listener");
    }

    if (unlink(socket_path.c_str()) < 0 && errno != ENOENT) {
        return tl::make_unexpected(errnoMessage(
            "Failed to remove stale UDS socket '" + socket_path + "'"));
    }
    LOG(INFO) << "Removed stale UDS socket file " << socket_path;
    return {};
}

}  // namespace

bool isFilesystemUdsPath(const std::string &socket_name) {
    return !socket_name.empty() && socket_name[0] == '/';
}

UdsConnection::UdsConnection(int fd) : fd_(fd) {}

UdsConnection::~UdsConnection() { close(); }

UdsConnection::UdsConnection(UdsConnection &&other) noexcept
    : fd_(other.release()) {}

UdsConnection &UdsConnection::operator=(UdsConnection &&other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.release();
    }
    return *this;
}

bool UdsConnection::valid() const { return fd_ >= 0; }

int UdsConnection::fd() const { return fd_; }

int UdsConnection::release() {
    int fd = fd_;
    fd_ = -1;
    return fd;
}

void UdsConnection::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

tl::expected<void, std::string> UdsConnection::setRecvTimeout(
    std::chrono::seconds timeout) {
    timeval tv = {.tv_sec = timeout.count(), .tv_usec = 0};
    if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return tl::make_unexpected(
            errnoMessage("Failed to set UDS recv timeout"));
    }
    return {};
}

int UdsConnection::sendRaw(const void *data, size_t len) {
    const char *pos = static_cast<const char *>(data);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t sent = ::send(fd_, pos, remaining, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return -1;
        pos += sent;
        remaining -= static_cast<size_t>(sent);
    }
    return 0;
}

int UdsConnection::recvRaw(void *data, size_t len) {
    char *pos = static_cast<char *>(data);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t received = ::recv(fd_, pos, remaining, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return -1;
        pos += received;
        remaining -= static_cast<size_t>(received);
    }
    return 0;
}

int UdsConnection::sendFd(int fd, void *data, size_t data_len) {
    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    iovec iov;
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));

    iov.iov_base = data;
    iov.iov_len = data_len;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    while (true) {
        ssize_t sent = sendmsg(fd_, &msg, 0);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0) return -1;
        return sent == static_cast<ssize_t>(data_len) ? 0 : -1;
    }
}

int UdsConnection::recvFd(void *data, size_t data_len) {
    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    iovec iov;
    char buf[CMSG_SPACE(sizeof(int))];
    memset(buf, 0, sizeof(buf));

    iov.iov_base = data;
    iov.iov_len = data_len;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    ssize_t received = 0;
    while (true) {
        received = recvmsg(fd_, &msg, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return -1;
        break;
    }

    cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
        int received_fd = -1;
        memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));
        // Even for malformed messages, close any delivered fd instead of
        // leaking it into this process.
        if (received != static_cast<ssize_t>(data_len) ||
            (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
            ::close(received_fd);
            return -1;
        }
        return received_fd;
    }
    return -1;
}

UdsConnector::UdsConnector(std::string socket_name,
                           std::chrono::milliseconds connect_timeout)
    : socket_name_(std::move(socket_name)), connect_timeout_(connect_timeout) {}

tl::expected<std::unique_ptr<UdsConnection>, std::string>
UdsConnector::connect() {
    auto fd = createConnectedSocket(socket_name_, connect_timeout_);
    if (!fd) return tl::make_unexpected(fd.error());
    return std::make_unique<UdsConnection>(*fd);
}

UdsAcceptor::UdsAcceptor(std::string socket_name, mode_t socket_mode)
    : socket_name_(std::move(socket_name)), socket_mode_(socket_mode) {}

UdsAcceptor::~UdsAcceptor() { stop(); }

void UdsAcceptor::registerHandler(Handler handler) {
    handler_ = std::move(handler);
}

tl::expected<void, std::string> UdsAcceptor::start() {
    if (running_.load()) return {};
    if (!handler_) {
        return tl::make_unexpected("UDS acceptor handler is not registered");
    }

    listen_fd_ = createCloexecUdsSocket();
    if (listen_fd_ < 0) {
        return tl::make_unexpected(errnoMessage("Failed to create UDS socket"));
    }

    sockaddr_un addr;
    socklen_t addr_len = 0;
    auto addr_result = makeAddress(socket_name_, addr, addr_len);
    if (!addr_result) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return tl::make_unexpected(addr_result.error());
    }

    const bool filesystem = isFilesystemUdsPath(socket_name_);
    if (filesystem) {
        auto remove_result = removeStaleSocketFile(socket_name_);
        if (!remove_result) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return tl::make_unexpected(remove_result.error());
        }
    }

    if (bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), addr_len) < 0) {
        auto error =
            errnoMessage("Failed to bind UDS socket '" + socket_name_ + "'");
        ::close(listen_fd_);
        listen_fd_ = -1;
        return tl::make_unexpected(error);
    }

    if (filesystem) {
        struct stat st;
        if (stat(socket_name_.c_str(), &st) == 0) {
            bound_socket_file_ = true;
            bound_dev_ = st.st_dev;
            bound_ino_ = st.st_ino;
        }
        // chmod before listen() so no client can connect under the
        // umask-derived mode.
        if (chmod(socket_name_.c_str(), socket_mode_) < 0) {
            auto error = errnoMessage("Failed to chmod UDS socket '" +
                                      socket_name_ + "'");
            ::close(listen_fd_);
            listen_fd_ = -1;
            unlinkBoundSocketFile();
            return tl::make_unexpected(error);
        }
    }

    if (listen(listen_fd_, 5) < 0) {
        auto error = errnoMessage("Failed to listen on UDS socket '" +
                                  socket_name_ + "'");
        ::close(listen_fd_);
        listen_fd_ = -1;
        unlinkBoundSocketFile();
        return tl::make_unexpected(error);
    }

    if (filesystem) {
        char mode_str[8];
        snprintf(mode_str, sizeof(mode_str), "%04o",
                 static_cast<unsigned>(socket_mode_));
        LOG(INFO) << "UDS acceptor listening on filesystem socket "
                  << socket_name_ << " (mode " << mode_str << ")";
    } else {
        LOG(INFO) << "UDS acceptor listening on abstract socket "
                  << socket_name_;
    }

    running_ = true;
    thread_ = std::thread([this]() { acceptLoop(); });
    return {};
}

void UdsAcceptor::stop() {
    if (!running_.exchange(false)) return;
    wakeAccept();
    int active_client_fd = active_client_fd_.load();
    if (active_client_fd >= 0) {
        // Stop should unblock handlers waiting on either read or write.
        ::shutdown(active_client_fd, SHUT_RDWR);
    }
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    unlinkBoundSocketFile();
}

void UdsAcceptor::unlinkBoundSocketFile() {
    if (!bound_socket_file_) return;
    bound_socket_file_ = false;
    struct stat st;
    if (lstat(socket_name_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode) &&
        st.st_dev == bound_dev_ && st.st_ino == bound_ino_) {
        ::unlink(socket_name_.c_str());
    }
}

void UdsAcceptor::acceptLoop() {
    while (running_.load()) {
        int client_sock = accept(listen_fd_, nullptr, nullptr);
        if (client_sock < 0) {
            if (running_.load()) {
                LOG(ERROR) << "Accept failed: " << strerror(errno);
            }
            continue;
        }

        UdsConnection connection(client_sock);
        if (!running_.load()) break;

        active_client_fd_ = connection.fd();
        if (handler_) handler_(connection);
        active_client_fd_ = -1;
    }
}

void UdsAcceptor::wakeAccept() {
    // accept() is a blocking syscall on the listener thread. Shutting down the
    // listener wakes accept() so the loop can observe running_ == false.
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
    }
}

}  // namespace mooncake
