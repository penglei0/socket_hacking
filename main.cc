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
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

enum Mode { ZERO_COPY = 0, STANDARD_MODE = 1 };

enum Type { TIME_BASED = 0, LOOP_BASED = 1 };

struct Config {
  Mode mode;
  Type type;
  int value;
  int size;
  std::string ip = "127.0.0.1";
};

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
    std::cout << "recvmsg notification: EAGAIN, ret= " << ret << std::endl;
    std::cout << errno << std::endl;
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
  int tmp = 1 << 21;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tmp, sizeof(int)) < 0) {
    throw std::runtime_error("setsockopt error");
  }
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

void udp_send_test(const Config &config) {
  int fd = create_udp_socket(12340, config.mode == ZERO_COPY);
  auto start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  auto end_time = start_time;
  auto sz = config.size;

  int i = 0;
  std::string buf(sz, 'a');

  int flags = config.mode == ZERO_COPY ? MSG_ZEROCOPY : 0;
  std::cout << "sending data to " << config.ip << std::endl;
  while (true) {
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(config.ip.c_str());
    dst_addr.sin_port = htons(12345);
    int n = sendto(fd, buf.c_str(), buf.size(), flags,
                   reinterpret_cast<const struct sockaddr *>(&dst_addr),
                   sizeof(dst_addr));
    if (n < 0) {
      throw std::runtime_error("sendto error");
    }
    // On a send call with MSG_ZEROCOPY, the kernel pins the user pages and
    // creates skbuff fragments directly from these pages.On tx completion,it
    // notifies the socket owner that it is safe to modify memory by queuing a
    // completion notification onto the socket error queue.
    while (!do_poll(fd, POLLOUT)) {
      if (config.mode == ZERO_COPY) {
        while (do_recv_completion(fd)) {
        }
      }
    }

    i++;

    if (config.type == LOOP_BASED) {
      if (i >= config.value) break;
      continue;
    }

    auto now_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    if (now_time - start_time >= config.value * 1000) {
      break;
    }
  }

  end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  std::cout << "[udp_send_test] zero copy is "
            << (config.mode == ZERO_COPY ? "enabled" : "disabled") << ", send "
            << (end_time - start_time) << " ms " << i
            << " times , with buff size " << sz << " bytes" << std::endl;
}

void usage() {
  std::cout << "Usage: program -m <mode> -t <type> -v <value> -s <size>"
            << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout
      << "  -m <mode>  : Run mode. 0 for zero-copy mode, 1 for standard mode."
      << std::endl;
  std::cout << "  -t <type>  : Run type. 0 for time-based run (in seconds), 1 "
               "for loop-based run."
            << std::endl;
  std::cout << "  -v <value> : Run value. Time in seconds if type is 0, loop "
               "count if type is 1."
            << std::endl;
  std::cout << "  -s <size>  : send buff size in bytes." << std::endl;
  std::cout << "  -c <ip address>  : ip address of the remote peer."
            << std::endl;
}

bool parse_arguments(int argc, const char *argv[], Config &config) {
  if (argc < 9) {
    usage();
    return false;
  }

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-m") {
      if (i + 1 < argc) {
        int mode = std::atoi(argv[++i]);
        if (mode == 0 || mode == 1) {
          config.mode = static_cast<Mode>(mode);
        } else {
          std::cerr << "Invalid mode value. Please use 0 or 1." << std::endl;
          return false;
        }
      } else {
        std::cerr << "-m option requires a value." << std::endl;
        usage();
        return false;
      }
    } else if (arg == "-t") {
      if (i + 1 < argc) {
        int type = std::atoi(argv[++i]);
        if (type == 0 || type == 1) {
          config.type = static_cast<Type>(type);
        } else {
          std::cerr << "Invalid type value. Please use 0 or 1." << std::endl;
          return false;
        }
      } else {
        std::cerr << "-t option requires a value." << std::endl;
        usage();
        return false;
      }
    } else if (arg == "-v") {
      if (i + 1 < argc) {
        config.value = std::atoi(argv[++i]);
      } else {
        std::cerr << "-v option requires a value." << std::endl;
        usage();
        return false;
      }
    } else if (arg == "-s") {
      if (i + 1 < argc) {
        config.size = std::atoi(argv[++i]);
      } else {
        std::cerr << "-s option requires a value." << std::endl;
        usage();
        return false;
      }
    } else if (arg == "-c") {
      if (i + 1 < argc) {
        config.ip = std::string(argv[++i]);
      } else {
        std::cerr << "-c option requires a ip address." << std::endl;
        usage();
        return false;
      }
    } else {
      std::cerr << "Unknown option: " << arg << std::endl;
      usage();
      return false;
    }
  }

  return true;
}

int main(int argc, const char **argv) {
  Config config;

  if (!parse_arguments(argc, argv, config)) {
    return 1;
  }

  udp_send_test(config);

  return 0;
}