#ifndef NET_CAPTURE_RING_BUFFER_H
#define NET_CAPTURE_RING_BUFFER_H

#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <limits.h>
#include "net/capture/callbacks.h"

namespace net {
  namespace capture {
    // Ring buffer.
    class ring_buffer {
      public:
        static constexpr const size_t min_block_size = 128;
        static constexpr const size_t max_block_size = ULONG_MAX;
        static constexpr const size_t
               default_block_size = static_cast<size_t>(1) << 12;

        static constexpr const size_t min_frame_size = 128;
        static constexpr const size_t max_frame_size = ULONG_MAX;
        static constexpr const size_t
               default_frame_size = static_cast<size_t>(1) << 11;

        static constexpr const size_t min_frames = 8;
        static constexpr const size_t max_frames = ULONG_MAX;
        static constexpr const size_t
               default_frames = static_cast<size_t>(1) << 9;

        // Constructor.
        ring_buffer() = default;

        // Destructor.
        ~ring_buffer();

        // Clear.
        void clear();

        // Create.
        bool create(const char* interface,
                    int rcvbuf_size,
                    bool promiscuous_mode,
                    size_t block_size,
                    size_t frame_size,
                    size_t frame_count);

        bool create(unsigned ifindex,
                    int rcvbuf_size,
                    bool promiscuous_mode,
                    size_t block_size,
                    size_t frame_size,
                    size_t frame_count);

        // Loop.
        bool loop(const callbacks& callbacks, void* user = nullptr);

        // Stop.
        void stop();

        // Show statistics.
        bool show_statistics();

      private:
        int _M_fd = -1;

        void* _M_buf = MAP_FAILED;
        size_t _M_ring_size;

        // For TPACKET_V2:
        //   _M_count = req.tp_frame_nr
        //   _M_size = req.tp_frame_size
        //
        // For TPACKET_V3:
        //   _M_count = req3.tp_block_nr
        //   _M_size = req3.tp_block_size
        size_t _M_count;
        size_t _M_size;

        size_t _M_nframes;

        struct iovec* _M_frames = nullptr;

        size_t _M_idx = 0;

        // Callbacks.
        callbacks _M_callbacks;
        void* _M_user;

        // Running?
        bool _M_running = false;

        // Set up socket.
        bool setup_socket(int rcvbuf_size);

        // Set up packet ring.
        bool setup_ring(size_t block_size,
                        size_t frame_size,
                        size_t frame_count);

        // Set up mmap packet ring.
        bool mmap_ring();

        // Bind packet ring.
        bool bind_ring(unsigned ifindex, bool promiscuous_mode);

#if HAVE_TPACKET_V3
        // Configure for TPACKET_V3.
        void config_v3(size_t block_size,
                       size_t frame_size,
                       size_t frame_count,
                       struct tpacket_req3& req);

        // Receive packet for TPACKET_V3.
        bool recv_v3();
#else
        // Configure for TPACKET_V2.
        void config_v2(size_t block_size,
                       size_t frame_size,
                       size_t frame_count,
                       struct tpacket_req& req);

        // Receive packet for TPACKET_V2.
        bool recv_v2();
#endif

        // Disable copy constructor and assignment operator.
        ring_buffer(const ring_buffer&) = delete;
        ring_buffer& operator=(const ring_buffer&) = delete;
    };

    inline ring_buffer::~ring_buffer()
    {
      clear();
    }

    inline bool ring_buffer::create(const char* interface,
                                    int rcvbuf_size,
                                    bool promiscuous_mode,
                                    size_t block_size,
                                    size_t frame_size,
                                    size_t frame_count)
    {
      return create(if_nametoindex(interface),
                    rcvbuf_size,
                    promiscuous_mode,
                    block_size,
                    frame_size,
                    frame_count);
    }

    inline void ring_buffer::stop()
    {
      _M_running = false;
    }
  }
}

#endif // NET_CAPTURE_RING_BUFFER_H
