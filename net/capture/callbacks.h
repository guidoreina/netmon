#ifndef NET_CAPTURE_CALLBACKS_H
#define NET_CAPTURE_CALLBACKS_H

#include <sys/types.h>
#include <time.h>

namespace net {
  namespace capture {
    // Capture callbacks.
    struct callbacks {
      typedef bool (*ethernet_t)(const void* buf,
                                 size_t len,
                                 const struct timeval& timestamp,
                                 void* user);

      typedef void (*idle_t)(void* user);

      // Constructor.
      callbacks() = default;
      callbacks(ethernet_t ethernet, idle_t idle);

      ethernet_t ethernet = nullptr;
      idle_t idle = nullptr;
    };

    inline callbacks::callbacks(ethernet_t ethernet, idle_t idle)
      : ethernet(ethernet),
        idle(idle)
    {
    }
  }
}

#endif // NET_CAPTURE_CALLBACKS_H
