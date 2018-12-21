#include <memory>
#include "net/mon/workers.h"

bool net::mon::workers::create(size_t nworkers,
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
                               uint64_t tcp_time_wait)
{
  if ((nworkers >= min_workers) &&
      (nworkers <= max_workers) &&
      (buffer_size >= event::writer::min_buffer_size)) {
    // Create threads.
    for (size_t i = 0; i < nworkers; i++) {
      if ((_M_workers[i] = new (std::nothrow) worker(i,
                                                     processors[i],
                                                     evdir,
                                                     file_allocation_size,
                                                     buffer_size)) == nullptr) {
        _M_nworkers = i;
        return false;
      }
    }

    _M_nworkers = nworkers;

    // Initialize threads.
    if (capture_method == capture::method::ring_buffer) {
      for (size_t i = 0; i < nworkers; i++) {
        if (!_M_workers[i]->init(device,
                                 ifindex,
                                 rcvbuf_size,
                                 promiscuous_mode,
                                 ring_buffer_block_size,
                                 ring_buffer_frame_size,
                                 ring_buffer_frame_count,
                                 tcp_ipv4_size,
                                 tcp_ipv4_maxconns,
                                 tcp_ipv6_size,
                                 tcp_ipv6_maxconns,
                                 tcp_timeout,
                                 tcp_time_wait)) {
          return false;
        }
      }
    } else {
      for (size_t i = 0; i < nworkers; i++) {
        if (!_M_workers[i]->init(device,
                                 ifindex,
                                 rcvbuf_size,
                                 promiscuous_mode,
                                 tcp_ipv4_size,
                                 tcp_ipv4_maxconns,
                                 tcp_ipv6_size,
                                 tcp_ipv6_maxconns,
                                 tcp_timeout,
                                 tcp_time_wait)) {
          return false;
        }
      }
    }

    return true;
  }

  return false;
}
