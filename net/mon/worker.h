#ifndef NET_MON_WORKER_H
#define NET_MON_WORKER_H

#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>
#include <limits.h>
#include "net/mon/tcp/connections.h"
#include "net/mon/ipv4/tcp/connection.h"
#include "net/mon/ipv6/tcp/connection.h"
#include "net/mon/event/writer.h"
#include "net/capture/ring_buffer.h"
#include "net/capture/socket.h"
#include "net/capture/method.h"
#include "net/parser.h"

namespace net {
  namespace mon {
    class worker {
      public:
        // No processor.
        static constexpr const size_t no_processor = ULONG_MAX;

        // Default directory where to save the event files.
        static constexpr const char* const default_directory = ".";

        // Constructor.
        worker(size_t nworker,
               size_t nprocessor,
               const char* evdir,
               uint64_t file_allocation_size,
               size_t buffer_size);

        // Destructor.
        ~worker();

        // Initialize.
        bool init(const char* device,
                  unsigned ifindex,
                  int rcvbuf_size,
                  bool promiscuous_mode,
                  size_t ring_buffer_block_size,
                  size_t ring_buffer_frame_size,
                  size_t ring_buffer_frame_count,
                  size_t tcp_ipv4_size,
                  size_t tcp_ipv4_maxconns,
                  size_t tcp_ipv6_size,
                  size_t tcp_ipv6_maxconns,
                  uint64_t tcp_timeout,
                  uint64_t tcp_time_wait);

        bool init(const char* device,
                  unsigned ifindex,
                  int rcvbuf_size,
                  bool promiscuous_mode,
                  size_t tcp_ipv4_size,
                  size_t tcp_ipv4_maxconns,
                  size_t tcp_ipv6_size,
                  size_t tcp_ipv6_maxconns,
                  uint64_t tcp_timeout,
                  uint64_t tcp_time_wait);

        bool init(const char* device,
                  size_t tcp_ipv4_size,
                  size_t tcp_ipv4_maxconns,
                  size_t tcp_ipv6_size,
                  size_t tcp_ipv6_maxconns,
                  uint64_t tcp_timeout,
                  uint64_t tcp_time_wait);

        // Start.
        bool start();

        // Stop.
        void stop();

        // Process ethernet frame.
        bool process_ethernet(const void* buf,
                              size_t len,
                              const struct timeval& timestamp);

        // Process IPv4 packet.
        bool process_ipv4(const void* buf,
                          size_t len,
                          const struct timeval& timestamp);

        // Process IPv6 packet.
        bool process_ipv6(const void* buf,
                          size_t len,
                          const struct timeval& timestamp);

        // Remove expired connections.
        void remove_expired(uint64_t now);

        // Show statistics.
        bool show_statistics();

      private:
        // Check interval of the expired connections.
        static constexpr const time_t check_interval = 10;

        // Worker number.
        size_t _M_nworker;

        // Processor number.
        size_t _M_nprocessor;

        // Directory where to save the event files.
        const char* const _M_evdir;

        // Capture method.
        capture::method _M_capture_method;

        // Ring buffer.
        capture::ring_buffer _M_ring_buffer;

        // Raw socket.
        capture::socket _M_socket;

        // Connection hash tables.
        tcp::connections<ipv4::tcp::connection> _M_tcp_ipv4;
        tcp::connections<ipv6::tcp::connection> _M_tcp_ipv6;

        // Parser.
        parser _M_parser;

        // Event writer.
        event::writer _M_evwriter;

        // Thread.
        pthread_t _M_thread;

        // Last check.
        time_t _M_last_check;

        // Running?
        bool _M_running = false;

        // Process ethernet frame.
        static bool process_ethernet(const void* buf,
                                     size_t len,
                                     const struct timeval& timestamp,
                                     void* user);

        // Process ICMP datagram.
        static bool icmp(const struct iphdr* iphdr,
                         size_t iphdrsize,
                         size_t pktsize,
                         const struct timeval& timestamp,
                         void* user);

        // Process ICMPv6 datagram.
        static bool icmpv6(const struct ip6_hdr* iphdr,
                           size_t iphdrsize,
                           size_t pktsize,
                           const struct timeval& timestamp,
                           void* user);

        // Process TCP/IPv4 segment.
        static bool tcp_ipv4(const struct iphdr* iphdr,
                             size_t iphdrsize,
                             size_t pktsize,
                             const struct timeval& timestamp,
                             void* user);

        // Process TCP/IPv6 segment.
        static bool tcp_ipv6(const struct ip6_hdr* iphdr,
                             size_t iphdrsize,
                             size_t pktsize,
                             const struct timeval& timestamp,
                             void* user);

        // Process UDP/IPv4 datagram.
        static bool udp_ipv4(const struct iphdr* iphdr,
                             size_t iphdrsize,
                             size_t pktsize,
                             const struct timeval& timestamp,
                             void* user);

        // Process UDP/IPv6 datagram.
        static bool udp_ipv6(const struct ip6_hdr* iphdr,
                             size_t iphdrsize,
                             size_t pktsize,
                             const struct timeval& timestamp,
                             void* user);

        // Run.
        static void* run(void* arg);

        // Idle.
        static void idle(void* user);

        // To microseconds.
        static uint64_t to_microseconds(const struct timeval& tv);

        // Disable copy constructor and assignment operator.
        worker(const worker&) = delete;
        worker& operator=(const worker&) = delete;
    };

    inline worker::worker(size_t nworker,
                          size_t nprocessor,
                          const char* evdir,
                          uint64_t file_allocation_size,
                          size_t buffer_size)
      : _M_nworker(nworker),
        _M_nprocessor(nprocessor),
        _M_evdir(evdir),
        _M_tcp_ipv4(_M_evwriter),
        _M_tcp_ipv6(_M_evwriter),
        _M_parser(parser::callbacks(icmp,
                                    icmpv6,
                                    tcp_ipv4,
                                    tcp_ipv6,
                                    udp_ipv4,
                                    udp_ipv6), this),
        _M_evwriter(file_allocation_size, buffer_size),
        _M_last_check(time(nullptr))
    {
    }

    inline worker::~worker()
    {
      stop();
    }

    inline bool worker::init(const char* device,
                             unsigned ifindex,
                             int rcvbuf_size,
                             bool promiscuous_mode,
                             size_t ring_buffer_block_size,
                             size_t ring_buffer_frame_size,
                             size_t ring_buffer_frame_count,
                             size_t tcp_ipv4_size,
                             size_t tcp_ipv4_maxconns,
                             size_t tcp_ipv6_size,
                             size_t tcp_ipv6_maxconns,
                             uint64_t tcp_timeout,
                             uint64_t tcp_time_wait)
    {
      _M_capture_method = capture::method::ring_buffer;

      return ((_M_ring_buffer.create(ifindex,
                                     rcvbuf_size,
                                     promiscuous_mode,
                                     ring_buffer_block_size,
                                     ring_buffer_frame_size,
                                     ring_buffer_frame_count)) &&
              (init(device,
                    tcp_ipv4_size,
                    tcp_ipv4_maxconns,
                    tcp_ipv6_size,
                    tcp_ipv6_maxconns,
                    tcp_timeout,
                    tcp_time_wait)));
    }

    inline bool worker::init(const char* device,
                             unsigned ifindex,
                             int rcvbuf_size,
                             bool promiscuous_mode,
                             size_t tcp_ipv4_size,
                             size_t tcp_ipv4_maxconns,
                             size_t tcp_ipv6_size,
                             size_t tcp_ipv6_maxconns,
                             uint64_t tcp_timeout,
                             uint64_t tcp_time_wait)
    {
      _M_capture_method = capture::method::socket;

      return ((_M_socket.create(ifindex, rcvbuf_size, promiscuous_mode)) &&
              (init(device,
                    tcp_ipv4_size,
                    tcp_ipv4_maxconns,
                    tcp_ipv6_size,
                    tcp_ipv6_maxconns,
                    tcp_timeout,
                    tcp_time_wait)));
    }

    inline bool worker::init(const char* device,
                             size_t tcp_ipv4_size,
                             size_t tcp_ipv4_maxconns,
                             size_t tcp_ipv6_size,
                             size_t tcp_ipv6_maxconns,
                             uint64_t tcp_timeout,
                             uint64_t tcp_time_wait)
    {
      // Compose filename.
      char filename[128];
      snprintf(filename,
               sizeof(filename),
               "%s/events-%s.%04zu.bin",
               _M_evdir,
               device,
               _M_nworker);

      return ((_M_evwriter.init()) &&
              (_M_tcp_ipv4.init(tcp_ipv4_size,
                                tcp_ipv4_maxconns,
                                tcp_timeout,
                                tcp_time_wait)) &&
              (_M_tcp_ipv6.init(tcp_ipv6_size,
                                tcp_ipv6_maxconns,
                                tcp_timeout,
                                tcp_time_wait)) &&
              (_M_evwriter.open(filename)));
    }

    inline void worker::stop()
    {
      if (_M_running) {
        _M_running = false;

        if (_M_capture_method == capture::method::ring_buffer) {
          _M_ring_buffer.stop();
        } else {
          _M_socket.stop();
        }

        pthread_join(_M_thread, nullptr);
      }
    }

    inline bool worker::process_ethernet(const void* buf,
                                         size_t len,
                                         const struct timeval& timestamp)
    {
      return _M_parser.process_ethernet(buf, len, timestamp);
    }

    inline bool worker::process_ipv4(const void* buf,
                                     size_t len,
                                     const struct timeval& timestamp)
    {
      return _M_parser.process_ipv4(buf, len, timestamp);
    }

    inline bool worker::process_ipv6(const void* buf,
                                     size_t len,
                                     const struct timeval& timestamp)
    {
      return _M_parser.process_ipv6(buf, len, timestamp);
    }

    inline void worker::remove_expired(uint64_t now)
    {
      _M_tcp_ipv4.remove_expired(now);
      _M_tcp_ipv6.remove_expired(now);
    }

    inline bool worker::show_statistics()
    {
      printf("Worker %zu:\n", _M_nworker);

      if (_M_capture_method == capture::method::ring_buffer) {
        return _M_ring_buffer.show_statistics();
      } else {
        return _M_socket.show_statistics();
      }
    }

    inline void* worker::run(void* arg)
    {
      if (static_cast<worker*>(arg)->_M_capture_method ==
          capture::method::ring_buffer) {
        static_cast<worker*>(arg)->_M_ring_buffer.loop(
          capture::callbacks(process_ethernet, idle),
          arg
        );
      } else {
        static_cast<worker*>(arg)->_M_socket.loop(
          capture::callbacks(process_ethernet, idle),
          arg
        );
      }

      return nullptr;
    }

    inline bool worker::process_ethernet(const void* buf,
                                         size_t len,
                                         const struct timeval& timestamp,
                                         void* user)
    {
      return static_cast<worker*>(user)->process_ethernet(buf, len, timestamp);
    }

    inline void worker::idle(void* user)
    {
      // Flush event writer buffer (if not empty).
      static_cast<worker*>(user)->_M_evwriter.flush();

      // Get current time.
      struct timeval now;
      gettimeofday(&now, nullptr);

      // If we have to check now the expired connections...
      if (static_cast<worker*>(user)->_M_last_check + check_interval <=
          now.tv_sec) {
        static_cast<worker*>(user)->remove_expired(to_microseconds(now));

        static_cast<worker*>(user)->_M_last_check = now.tv_sec;
      }
    }

    inline uint64_t worker::to_microseconds(const struct timeval& tv)
    {
      return ((tv.tv_sec * 1000000ull) + tv.tv_usec);
    }
  }
}

#endif // NET_MON_WORKER_H
