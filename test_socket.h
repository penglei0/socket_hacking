#ifndef TEST_SOCKET_H
#define TEST_SOCKET_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <exception>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

enum TestSocketType {
  SocketTypeTcp,
  SocketTypeUdp,
  SocketTypeUnixDomain,
};

const std::string uds_socket_bind_path = "/tmp/uds_socket_bind_path_test";

template <TestSocketType type>
class TestSocket {
 public:
  TestSocket() {
    switch (type) {
      case SocketTypeTcp:
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        break;
      case SocketTypeUdp:
        fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        break;
      case SocketTypeUnixDomain:
        fd_ = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        break;
      default:
        throw std::runtime_error("invalid socket type");
    }
    // setup socket
    setup();
  }

  ~TestSocket() {
    if constexpr (type == SocketTypeUnixDomain) {
      unlink(uds_socket_bind_path.c_str());
    }
    close();
  }
  // disallow copy and assign
  TestSocket(const TestSocket&) = delete;
  TestSocket& operator=(const TestSocket&) = delete;
  // disallow move and move assign
  TestSocket(TestSocket&&) = delete;
  TestSocket& operator=(TestSocket&&) = delete;
  // interface
  int fd() const { return fd_; }
  int bind(int port = 0) {
    int ret = 0;
    if constexpr (type != SocketTypeUnixDomain) {
      ret = bind_inet(port);
    } else {
      ret = bind_unix(uds_socket_bind_path);
    }
    std::cout << "bind " << fd_ << " " << ret << std::endl;
    return ret;
  }
  int listen(int backlog) {
    std::cout << "listen " << fd_ << " " << backlog << std::endl;
    return ::listen(fd_, backlog);
  }
  int connect(const std::string& remote_addr, int port = 0) {
    if constexpr (type == SocketTypeUnixDomain) {
      struct sockaddr_un address;
      address.sun_family = AF_UNIX;
      snprintf(address.sun_path, sizeof(address.sun_path), "%s",
               remote_addr.c_str());
      return ::connect(fd_, reinterpret_cast<struct sockaddr*>(&address),
                       sizeof(address));
    }
    if (port == 0) {
      throw std::runtime_error("invalid port");
    }
    struct sockaddr_in server;
    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(remote_addr.c_str());
    return ::connect(fd_, reinterpret_cast<struct sockaddr*>(&server),
                     sizeof(server));
  }
  int send(const std::string& data) {
    return ::send(fd_, data.data(), data.size(), 0);
  }
  int recv(void* buf, size_t len, int flags) {
    return ::recv(fd_, buf, len, flags);
  }
  int close() {
    std::cout << "close " << fd_ << std::endl;
    shutdown(fd_, SHUT_RDWR);
    return ::close(fd_);
  }

 private:
  void setup() {
    int64_t on = 1L;
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0) {
      std::cout << "setsockopt error " << strerror(errno);
    }
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(int)) < 0) {
      std::cout << "setsockopt error " << strerror(errno);
    }
  }
  /// @brief for unix domain socket
  /// @return
  int bind_unix(const std::string& path) {
    struct sockaddr_un address;
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", path.c_str());
    return ::bind(fd_, reinterpret_cast<struct sockaddr*>(&address),
                  sizeof(address));
  }
  /// @brief for tcp socket or udp socket
  /// @return
  int bind_inet(int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    // Filling server information
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    // Bind the socket with the address
    return ::bind(fd_, reinterpret_cast<const struct sockaddr*>(&addr),
                  sizeof(addr));
  }
  int fd_;
};

template <TestSocketType server_type>
class TestServer {
 public:
  TestServer() {
    auto ret = socket_.bind();
    if (ret < 0) {
      throw std::runtime_error("bind failed");
    }
    ret = socket_.listen(10);
    if (ret < 0) {
      throw std::runtime_error("listen failed");
    }
  }
  ~TestServer() { stop(); }
  // disallow copy and assign
  TestServer(const TestServer&) = delete;
  TestServer& operator=(const TestServer&) = delete;
  // disallow move and move assign
  TestServer(TestServer&&) = delete;
  TestServer& operator=(TestServer&&) = delete;
  void wait_on_data() {
    // use `select` to wait for client connection
    int listen_fd = socket_.fd();
    while (is_stop_.load() == false) {
      fd_set readfds;
      FD_ZERO(&readfds);
      FD_SET(listen_fd, &readfds);
      for (auto fd : client_fds_) {
        FD_SET(fd, &readfds);
      }
      auto max_fd = std::max(
          listen_fd, *std::max_element(client_fds_.begin(), client_fds_.end()));
      struct timeval tv;
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      auto ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
      if (ret < 0) {
        std::cout << "select failed" << std::endl;
        return;
      } else if (ret == 0) {
        std::cout << "select timeout" << std::endl;
        return;
      }
      // listen fd is ready for read
      if (FD_ISSET(listen_fd, &readfds)) {
        std::cout << "client connected" << std::endl;
        // accept client connection
        struct sockaddr_un client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd =
            accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_fd < 0) {
          std::cout << "accept failed " << strerror(errno) << " " << listen_fd
                    << std::endl;
          return;
        }
        std::cout << "connection accepted from client "
                  << std::string(client_addr.sun_path) << std::endl;
        client_fds_.insert(client_fd);
        continue;
      }
      // client fd is ready for read
      for (auto it = client_fds_.begin(); it != client_fds_.end();) {
        auto fd = *it;
        if (FD_ISSET(fd, &readfds)) {
          char buf[1024];
          memset(buf, 0, sizeof(buf));
          auto ret = recv(fd, buf, sizeof(buf), 0);
          if (ret < 0) {
            std::cout << "recv failed" << std::endl;
            ++it;
            continue;
          } else if (ret == 0) {
            std::cout << "client disconnected" << std::endl;
            // fixbug: erase fd from set
            it = client_fds_.erase(it);
            close(fd);
            continue;
          }
          std::cout << "recv data: " << buf << std::endl;
        }
        ++it;
      }
    }
  }

  void stop() {
    is_stop_.exchange(true);
    for (auto fd : client_fds_) {
      close(fd);
    }
  }

 private:
  std::atomic<bool> is_stop_ = false;
  std::set<int> client_fds_;
  TestSocket<server_type> socket_;
};

#endif  // TEST_SOCKET_H