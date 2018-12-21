#ifndef NET_CAPTURE_SOCKET_H
#define NET_CAPTURE_SOCKET_H

#include <stdint.h>
#include <net/if.h>
#include "net/capture/callbacks.h"

namespace net {
  namespace capture {
    // Raw socket.
    class socket {
      public:
        // Constructor.
        socket() = default;

        // Destructor.
        ~socket();

        // Clear.
        void clear();

        // Create.
        bool create(const char* interface,
                    int rcvbuf_size,
                    bool promiscuous_mode);

        bool create(unsigned ifindex, int rcvbuf_size, bool promiscuous_mode);

        // Loop.
        bool loop(const callbacks& callbacks, void* user = nullptr);

        // Stop.
        void stop();

        // Show statistics.
        bool show_statistics();

      private:
        // Maximum number of messages to receive with one read operation.
        static constexpr const unsigned max_messages = 256;

        // Maximum message size.
        static constexpr const size_t max_message_size = 64 * 1024;

        int _M_fd = -1;

        struct mmsghdr _M_msg[max_messages];
        struct iovec _M_iov[max_messages];

        uint8_t* _M_buf = nullptr;

        // Callbacks.
        callbacks _M_callbacks;
        void* _M_user;

        // Running?
        bool _M_running = false;

        // Set up socket.
        bool setup_socket(int rcvbuf_size);

        // Bind.
        bool bind(unsigned ifindex, bool promiscuous_mode);

        // Receive packets.
        bool recv();

        // Disable copy constructor and assignment operator.
        socket(const socket&) = delete;
        socket& operator=(const socket&) = delete;
    };

    inline socket::~socket()
    {
      clear();
    }

    inline bool socket::create(const char* interface,
                               int rcvbuf_size,
                               bool promiscuous_mode)
    {
      return create(if_nametoindex(interface), rcvbuf_size, promiscuous_mode);
    }

    inline void socket::stop()
    {
      _M_running = false;
    }
  }
}

#endif // NET_CAPTURE_SOCKET_H
