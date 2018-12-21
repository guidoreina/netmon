#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <errno.h>
#include "net/capture/socket.h"
#include "net/capture/limits.h"

void net::capture::socket::clear()
{
  if (_M_fd != -1) {
    close(_M_fd);
    _M_fd = -1;
  }

  if (_M_buf) {
    free(_M_buf);
    _M_buf = nullptr;
  }
}

bool net::capture::socket::create(unsigned ifindex,
                                  int rcvbuf_size,
                                  bool promiscuous_mode)
{
  if ((ifindex > 0) &&
      ((rcvbuf_size == 0) || (rcvbuf_size >= min_rcvbuf_size))) {
    if ((setup_socket(rcvbuf_size)) &&
        (bind(ifindex, promiscuous_mode)) &&
        ((_M_buf = static_cast<uint8_t*>(
                     malloc(max_messages * max_message_size)
                   )) != nullptr)) {
#if defined(PACKET_FANOUT)
      // Create fanout group.
      int optval = ((PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG) << 16) |
                   ((getpid() ^ ifindex) & 0xffff);

      if (setsockopt(_M_fd,
                     SOL_PACKET,
                     PACKET_FANOUT,
                     &optval,
                     sizeof(int)) < 0) {
        return false;
      }
#endif // defined(PACKET_FANOUT)

      // Initialize messages.
      uint8_t* buf = _M_buf;
      for (size_t i = 0; i < max_messages; i++) {
        _M_iov[i].iov_base = buf;
        _M_iov[i].iov_len = max_message_size;

        _M_msg[i].msg_hdr.msg_name = nullptr;
        _M_msg[i].msg_hdr.msg_namelen = 0;
        _M_msg[i].msg_hdr.msg_iov = _M_iov + i;
        _M_msg[i].msg_hdr.msg_iovlen = 1;
        _M_msg[i].msg_hdr.msg_control = nullptr;
        _M_msg[i].msg_hdr.msg_controllen = 0;
        _M_msg[i].msg_hdr.msg_flags = 0;

        buf += max_message_size;
      }

      return true;
    }
  }

  return false;
}

bool net::capture::socket::loop(const callbacks& callbacks, void* user)
{
  static constexpr const int timeout = 100;

  _M_callbacks = callbacks;
  _M_user = user;

  struct pollfd pfd;
  pfd.fd = _M_fd;
  pfd.events = POLLIN;

  _M_running = true;

  do {
    switch (poll(&pfd, 1, timeout)) {
      case 1:
        recv();
        break;
      case 0: // Timeout.
        if (callbacks.idle) {
          callbacks.idle(user);
        }

        break;
      default:
        if (errno != EINTR) {
          return false;
        }
    }
  } while (_M_running);

  return true;
}

bool net::capture::socket::show_statistics()
{
  struct tpacket_stats stats;
  socklen_t optlen = static_cast<socklen_t>(sizeof(struct tpacket_stats));

  if (getsockopt(_M_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) == 0) {
    printf("  %u packets received.\n", stats.tp_packets);
    printf("  %u packets dropped by kernel.\n", stats.tp_drops);

    return true;
  }

  return false;
}

bool net::capture::socket::setup_socket(int rcvbuf_size)
{
  // Create socket.
  if ((_M_fd = ::socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) != -1) {
    if (rcvbuf_size != 0) {
      return (setsockopt(_M_fd,
                         SOL_SOCKET,
                         SO_RCVBUF,
                         &rcvbuf_size,
                         sizeof(int)) == 0);
    }

    return true;
  }

  return false;
}

bool net::capture::socket::bind(unsigned ifindex, bool promiscuous_mode)
{
  if (promiscuous_mode) {
    // Put the interface in promiscuous mode.
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(struct packet_mreq));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(_M_fd,
                   SOL_PACKET,
                   PACKET_ADD_MEMBERSHIP,
                   &mr,
                   sizeof(struct packet_mreq)) < 0) {
      return false;
    }
  }

  // Bind.
  struct sockaddr_ll addr;
  memset(&addr, 0, sizeof(struct sockaddr_ll));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex = ifindex;

  return (::bind(_M_fd,
                 reinterpret_cast<const struct sockaddr*>(&addr),
                 static_cast<socklen_t>(sizeof(struct sockaddr_ll))) == 0);
}

bool net::capture::socket::recv()
{
  // Receive messages.
  int nmsgs = recvmmsg(_M_fd,
                       _M_msg,
                       max_messages,
                       MSG_TRUNC | MSG_DONTWAIT,
                       nullptr);

  // If we have received at least one packet...
  if (nmsgs >= 1) {
    // Get timestamp of the last packet.
    struct timeval tv;
    if (ioctl(_M_fd, SIOCGSTAMP, &tv) != -1) {
      // For each received message...
      for (int i = 0; i < nmsgs; i++) {
        // Process packet.
        _M_callbacks.ethernet(_M_msg[i].msg_hdr.msg_iov->iov_base,
                              _M_msg[i].msg_len,
                              tv,
                              _M_user);
      }
    }
  }

  return true;
}
