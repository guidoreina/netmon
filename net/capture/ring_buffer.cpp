#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>

#if !defined(PACKET_TIMESTAMP)
  #include <sys/time.h>
#endif

#include <sys/uio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/net_tstamp.h>
#include <errno.h>
#include "net/capture/ring_buffer.h"
#include "net/capture/limits.h"

void net::capture::ring_buffer::clear()
{
  if (_M_buf != MAP_FAILED) {
    munmap(_M_buf, _M_ring_size);
    _M_buf = MAP_FAILED;
  }

  if (_M_fd != -1) {
    close(_M_fd);
    _M_fd = -1;
  }

  if (_M_frames) {
    free(_M_frames);
    _M_frames = nullptr;
  }

  _M_idx = 0;
}

bool net::capture::ring_buffer::create(unsigned ifindex,
                                       int rcvbuf_size,
                                       bool promiscuous_mode,
                                       size_t block_size,
                                       size_t frame_size,
                                       size_t frame_count)
{
  if ((ifindex > 0) &&
      ((rcvbuf_size == 0) || (rcvbuf_size >= min_rcvbuf_size)) &&
      (block_size >= min_block_size) &&
      (block_size <= max_block_size) &&
      (frame_size >= min_frame_size) &&
      (frame_size <= max_frame_size) &&
      (frame_count >= min_frames) &&
      (frame_count <= max_frames) &&
      (frame_size <= block_size)) {
    if ((setup_socket(rcvbuf_size)) &&
        (setup_ring(block_size, frame_size, frame_count)) &&
        (mmap_ring()) &&
        (bind_ring(ifindex, promiscuous_mode))) {
#if defined(PACKET_FANOUT)
      // Create fanout group.
      int optval = ((PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG) << 16) |
                   ((getpid() ^ ifindex) & 0xffff);

      return (setsockopt(_M_fd,
                         SOL_PACKET,
                         PACKET_FANOUT,
                         &optval,
                         sizeof(int)) == 0);
#else
      return true;
#endif
    }
  }

  return false;
}

bool net::capture::ring_buffer::loop(const callbacks& callbacks, void* user)
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
#if HAVE_TPACKET_V3
        recv_v3();
#else
        recv_v2();
#endif

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

bool net::capture::ring_buffer::show_statistics()
{
#if HAVE_TPACKET_V3
  struct tpacket_stats_v3 stats;
#else
  struct tpacket_stats stats;
#endif

  socklen_t optlen = static_cast<socklen_t>(sizeof(stats));

  if (getsockopt(_M_fd, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) == 0) {
    printf("  %u packets received.\n", stats.tp_packets);
    printf("  %u packets dropped by kernel.\n", stats.tp_drops);

    return true;
  }

  return false;
}

bool net::capture::ring_buffer::setup_socket(int rcvbuf_size)
{
  // Create socket.
  if ((_M_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) != -1) {
    if (rcvbuf_size != 0) {
      if (setsockopt(_M_fd,
                     SOL_SOCKET,
                     SO_RCVBUF,
                     &rcvbuf_size,
                     sizeof(int)) < 0) {
        return false;
      }
    }

#if HAVE_TPACKET_V3
    int optval = static_cast<int>(TPACKET_V3);
#else
    int optval = static_cast<int>(TPACKET_V2);
#endif

    // Set packet version.
    if (setsockopt(_M_fd,
                   SOL_PACKET,
                   PACKET_VERSION,
                   &optval,
                   sizeof(int)) == 0) {
#if defined(PACKET_TIMESTAMP)
      // Enable packet timestamp.
      optval = SOF_TIMESTAMPING_RAW_HARDWARE;
      return (setsockopt(_M_fd,
                         SOL_PACKET,
                         PACKET_TIMESTAMP,
                         &optval,
                         sizeof(int)) == 0);
#else
      return true;
#endif
    }
  }

  return false;
}

bool net::capture::ring_buffer::setup_ring(size_t block_size,
                                           size_t frame_size,
                                           size_t frame_count)
{
#if HAVE_TPACKET_V3
    struct tpacket_req3 req;
    config_v3(block_size, frame_size, frame_count, req);
#else
    struct tpacket_req req;
    config_v2(block_size, frame_size, frame_count, req);
#endif

  return (setsockopt(_M_fd,
                     SOL_PACKET,
                     PACKET_RX_RING,
                     &req,
                     static_cast<socklen_t>(sizeof(req))) == 0);
}

bool net::capture::ring_buffer::mmap_ring()
{
  // Map ring into memory.
  if ((_M_buf = mmap(nullptr,
                     _M_ring_size,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_LOCKED,
                     _M_fd,
                     0)) != MAP_FAILED) {
    // Allocate frames.
    if ((_M_frames = reinterpret_cast<struct iovec*>(
                       malloc(_M_count * sizeof(struct iovec))
                     )) != nullptr) {
      uint8_t* buf = reinterpret_cast<uint8_t*>(_M_buf);

      for (size_t i = 0; i < _M_count; i++) {
        _M_frames[i].iov_base = buf;
        _M_frames[i].iov_len = _M_size;

        buf += _M_size;
      }

      return true;
    }
  }

  return false;
}

bool net::capture::ring_buffer::bind_ring(unsigned ifindex,
                                          bool promiscuous_mode)
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

  return (bind(_M_fd,
               reinterpret_cast<const struct sockaddr*>(&addr),
               static_cast<socklen_t>(sizeof(struct sockaddr_ll))) == 0);
}

#if HAVE_TPACKET_V3
  void net::capture::ring_buffer::config_v3(size_t block_size,
                                            size_t frame_size,
                                            size_t frame_count,
                                            struct tpacket_req3& req)
  {
    memset(&req, 0, sizeof(struct tpacket_req3));

    // Calculate number of blocks.
    size_t block_count = frame_count / (block_size / frame_size);

    req.tp_block_nr = block_count;
    req.tp_block_size = block_size;
    req.tp_frame_nr = frame_count;
    req.tp_frame_size = frame_size;

    req.tp_retire_blk_tov = 64;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    _M_ring_size = block_count * block_size;

    _M_count = block_count;
    _M_size = block_size;
  }

  bool net::capture::ring_buffer::recv_v3()
  {
    struct tpacket_block_desc* block_desc =
                               reinterpret_cast<struct tpacket_block_desc*>(
                                 _M_frames[_M_idx].iov_base
                               );

    // If there is a new block...
    if ((block_desc->hdr.bh1.block_status & TP_STATUS_USER) != 0) {
      struct tpacket3_hdr* hdr = reinterpret_cast<struct tpacket3_hdr*>(
                                   reinterpret_cast<uint8_t*>(block_desc) +
                                   block_desc->hdr.bh1.offset_to_first_pkt
                                 );

      struct timeval tv;

#if !defined(PACKET_TIMESTAMP)
      // Get current time.
      gettimeofday(&tv, nullptr);
#endif // !defined(PACKET_TIMESTAMP)

      uint32_t num_pkts = block_desc->hdr.bh1.num_pkts;

      // Process packets in the block.
      for (uint32_t i = 0; i < num_pkts; i++) {
#if defined(PACKET_TIMESTAMP)
        tv.tv_sec = hdr->tp_sec;
        tv.tv_usec = hdr->tp_nsec / 1000;
#endif // defined(PACKET_TIMESTAMP)

        _M_callbacks.ethernet(reinterpret_cast<const uint8_t*>(hdr) +
                              hdr->tp_mac,
                              hdr->tp_snaplen,
                              tv,
                              _M_user);

        hdr = reinterpret_cast<struct tpacket3_hdr*>(
                reinterpret_cast<uint8_t*>(hdr) + hdr->tp_next_offset
              );
      }

      // Mark block as free.
      block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;

      _M_idx = (_M_idx + 1) % _M_count;

      return true;
    } else {
      return false;
    }
  }
#else
  void net::capture::ring_buffer::config_v2(size_t block_size,
                                            size_t frame_size,
                                            size_t frame_count,
                                            struct tpacket_req& req)
  {
    memset(&req, 0, sizeof(struct tpacket_req));

    // Calculate number of blocks.
    size_t block_count = frame_count / (block_size / frame_size);

    req.tp_block_nr = block_count;
    req.tp_block_size = block_size;
    req.tp_frame_nr = frame_count;
    req.tp_frame_size = frame_size;

    _M_ring_size = block_count * block_size;

    _M_count = frame_count;
    _M_size = frame_size;
  }

  bool net::capture::ring_buffer::recv_v2()
  {
    struct tpacket2_hdr* hdr = reinterpret_cast<struct tpacket2_hdr*>(
                                 _M_frames[_M_idx].iov_base
                               );

    // If there is a new packet...
    if ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER) {
      struct timeval tv;

#if defined(PACKET_TIMESTAMP)
      tv.tv_sec = hdr->tp_sec;
      tv.tv_usec = hdr->tp_nsec / 1000;
#else
      // Get current time.
      gettimeofday(&tv, nullptr);
#endif

      // Process packet.
      _M_callbacks.ethernet(reinterpret_cast<const uint8_t*>(hdr) + hdr->tp_mac,
                            hdr->tp_snaplen,
                            tv,
                            _M_user);

      // Mark frame as free.
      hdr->tp_status = TP_STATUS_KERNEL;

      _M_idx = (_M_idx + 1) % _M_count;

      return true;
    } else {
      return false;
    }
  }
#endif
