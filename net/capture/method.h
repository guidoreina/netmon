#ifndef NET_CAPTURE_METHOD_H
#define NET_CAPTURE_METHOD_H

namespace net {
  namespace capture {
    // Capture method.
    enum class method {
      ring_buffer,
      socket
    };
  }
}

#endif // NET_CAPTURE_METHOD_H
