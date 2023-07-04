#include <signal.h>

#include <thread>

#include "test_socket.h"

template <TestSocketType sock_type>
void test_send_recv(TestServer<sock_type> &ts_server) {
  std::thread t([&ts_server]() { ts_server.wait_on_data(); });

  // client
  TestSocket<sock_type> ts_client;
  auto ret = ts_client.connect(uds_socket_bind_path);
  if (ret < 0) {
    std::cout << "client connect failed" << std::endl;
    return;
  }
  int cnt = 0;
  while (cnt++ <= 3) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    ts_client.send("hello");
  }

  ts_client.close();
  std::this_thread::sleep_for(std::chrono::seconds(1));
  ts_server.stop();
  t.detach();
}

void sig_handler(int sig) {
  std::cout << "sig_handler " << sig << std::endl;
  exit(0);
}

int main(int argc, const char **argv) {
  // ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);
  // capture SIGINT
  signal(SIGINT, sig_handler);

  // unix domain socket
  TestServer<SocketTypeUnixDomain> ts_server;
  test_send_recv(ts_server);
  return 0;
}