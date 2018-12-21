#ifndef NET_MON_EVENT_TCP_BEGIN_H
#define NET_MON_EVENT_TCP_BEGIN_H

#include "net/mon/event/base.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'Begin TCP connection' event.
      struct tcp_begin : public base {
        static constexpr const type t = type::tcp_begin;

        // Source port.
        in_port_t sport;

        // Destination port.
        in_port_t dport;

        // Build 'Begin TCP connection' event.
        bool build(const void* buf, size_t len);

        // Get size.
        size_t size() const;

        // Serialize.
        bool serialize(string::buffer& buf) const;

        // Print human readable.
        void print_human_readable(FILE* file,
                                  printer::format fmt,
                                  const char* srchost,
                                  const char* dsthost) const;

        // Print JSON.
        void print_json(FILE* file,
                        printer::format fmt,
                        const char* srchost,
                        const char* dsthost) const;

        // Print CSV.
        void print_csv(FILE* file,
                       char separator,
                       const char* srchost,
                       const char* dsthost) const;
      };

      static_assert(sizeof(evlen_t) +
                    sizeof(type) +
                    sizeof(tcp_begin) <= maxlen,
                    "'maxlen' is smaller than sizeof(tcp_begin)");

      inline size_t tcp_begin::size() const
      {
        return base::size()      + // Size of the base event.
               sizeof(in_port_t) + // Source port.
               sizeof(in_port_t);  // Destination port.
      }
    }
  }
}

#endif // NET_MON_EVENT_TCP_BEGIN_H
