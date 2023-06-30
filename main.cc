#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <poll.h>  // For poll function and related constants
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

int do_poll(int fd, int events) {
  struct pollfd pfd;
  int ret;

  pfd.events = events;
  pfd.revents = 0;
  pfd.fd = fd;

  ret = poll(&pfd, 1, 500);
  if (ret == -1) {
    std::cout << "poll error" << std::endl;
  }
  return ret && (pfd.revents & events);
}

// receiving completions on the errqueue
bool do_recv_completion(int fd) {
  struct sock_extended_err *serr;
  struct msghdr msg = {};
  struct cmsghdr *cm;
  uint32_t hi, lo, range;
  int ret, zerocopy;
  char control[100];

  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  ret = recvmsg(fd, &msg, MSG_ERRQUEUE);
  if (ret == -1 && errno == EAGAIN) {
    // std::cout << "recvmsg notification: EAGAIN" << std::endl;
    return false;
  }
  if (ret == -1) {
    std::cout << "recvmsg notification" << std::endl;
  }
  if (msg.msg_flags & MSG_CTRUNC) {
    std::cout << "recvmsg notification: truncated" << std::endl;
  }
  // parse the message
  cm = CMSG_FIRSTHDR(&msg);
  if (!cm) {
    std::cout << "serr: no cmsg" << std::endl;
  }
  if (!((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR) ||
        (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR) ||
        (cm->cmsg_level == SOL_PACKET &&
         cm->cmsg_type == PACKET_TX_TIMESTAMP))) {
    std::cout << "serr: wrong type: " << cm->cmsg_level << "." << cm->cmsg_type
              << std::endl;
  }
  serr = (sock_extended_err *)CMSG_DATA(cm);

  if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY) {
    std::cout << "serr: wrong origin" << std::endl;
  }
  if (serr->ee_errno != 0) {
    std::cout << "serr: wrong error code: " << serr->ee_errno << std::endl;
  }
  hi = serr->ee_data;
  lo = serr->ee_info;
  std::cout << "serr: " << hi << " " << lo << std::endl;
  // printf("completed: %u..%u\n", serr->ee_info, serr->ee_data);
  return true;
}

int create_udp_socket(int port, bool enable_zerocopy = true) {
  // create a unix socket
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    std::cout << "socket error" << std::endl;
    return -1;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  int64_t temp = 1L;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &temp, sizeof(int)) < 0) {
    throw std::runtime_error("setsockopt error");
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &temp, sizeof(int)) < 0) {
    throw std::runtime_error("setsockopt error");
  }
  if (enable_zerocopy) {
    if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &temp, sizeof(temp)) < 0) {
      throw std::runtime_error("setsockopt error");
    }
  }

  // Bind the socket with the server address
  if (bind(fd, reinterpret_cast<const struct sockaddr *>(&addr),
           sizeof(addr)) == -1) {
    throw std::runtime_error("bind error");
  }
  return fd;
}

void udp_send_test(bool enable_zerocopy = true) {
  int fd = create_udp_socket(12340, enable_zerocopy);
  auto start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  int i = 0;
  while (i < 100000) {
    char buf[1024];
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr("10.53.1.65");
    dst_addr.sin_port = htons(12345);
    int n = sendto(fd, buf, sizeof(buf), enable_zerocopy ? SO_ZEROCOPY : 0,
                   reinterpret_cast<const struct sockaddr *>(&dst_addr),
                   sizeof(dst_addr));
    if (n < 0) {
      throw std::runtime_error("sendto error");
    }
    // On a send call with MSG_ZEROCOPY, the kernel pins the user pages and
    // creates skbuff fragments directly from these pages.On tx completion,it
    // notifies the socket owner that it is safe to modify memory by queuing a
    // completion notification onto the socket error queue.
    if (enable_zerocopy && do_poll(fd, POLLOUT)) {
      while (do_recv_completion(fd)) {
        // fixme?
      }
    }
    i++;
  }
  auto end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
  std::cout << "[udp_send_test] enable_zerocopy "
            << (enable_zerocopy ? "enable" : "disable") << "send "
            << (end_time - start_time) << " ms" << std::endl;
}

int main(int argc, const char **argv) {
  udp_send_test(false);
  udp_send_test(true);
  return 0;
}