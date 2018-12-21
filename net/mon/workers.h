#ifndef NET_MON_WORKERS_H
#define NET_MON_WORKERS_H

#include <sys/types.h>
#include "net/mon/worker.h"
#include "net/capture/method.h"

namespace net {
  namespace mon {
    class workers {
      public:
        static constexpr const size_t min_workers = 1;
        static constexpr const size_t max_workers = 1024;
        static constexpr const size_t default_workers = 4;

        // Constructor.
        workers() = default;

        // Destructor.
        ~workers();

        // Create workers.
        bool create(size_t nworkers,
                    const size_t* processors,
                    const char* evdir,
                    uint64_t file_allocation_size,
                    size_t buffer_size,
                    capture::method capture_method,
                    const char* device,
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

        // Start workers.
        bool start();

        // Stop workers.
        void stop();

        // Show statistics.
        bool show_statistics();

      private:
        // Workers.
        worker* _M_workers[max_workers];

        // Number of workers.
        size_t _M_nworkers = 0;

        // Disable copy constructor and assignment operator.
        workers(const workers&) = delete;
        workers& operator=(const workers&) = delete;
    };

    inline workers::~workers()
    {
      for (size_t i = 0; i < _M_nworkers; i++) {
        delete _M_workers[i];
      }
    }

    inline bool workers::start()
    {
      for (size_t i = 0; i < _M_nworkers; i++) {
        if (!_M_workers[i]->start()) {
          return false;
        }
      }

      return true;
    }

    inline void workers::stop()
    {
      for (size_t i = 0; i < _M_nworkers; i++) {
        _M_workers[i]->stop();
      }
    }

    inline bool workers::show_statistics()
    {
      for (size_t i = 0; i < _M_nworkers; i++) {
        if (!_M_workers[i]->show_statistics()) {
          return false;
        }
      }

      return true;
    }
  }
}

#endif // NET_MON_WORKERS_H
