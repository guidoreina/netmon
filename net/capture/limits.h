#ifndef NET_CAPTURE_LIMITS_H
#define NET_CAPTURE_LIMITS_H

namespace net {
  namespace capture {
    // Minimum size of the socket receive buffer.
    static constexpr const int min_rcvbuf_size = 2 * 1024;
  }
}

#endif // NET_CAPTURE_LIMITS_H
