#ifndef NET_MON_EVENT_TCP_DATA_H
#define NET_MON_EVENT_TCP_DATA_H

#include "net/mon/event/base.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'TCP data' event.
      struct tcp_data : public base {
        static constexpr const type t = type::tcp_data;

        // Source port.
        in_port_t sport;

        // Destination port.
        in_port_t dport;

        // # of bytes of payload.
        uint16_t payload;

        // Build 'TCP data' event.
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

      static_assert(sizeof(evlen_t) + sizeof(type) + sizeof(tcp_data) <= maxlen,
                    "'maxlen' is smaller than sizeof(tcp_data)");

      inline size_t tcp_data::size() const
      {
        return base::size()      + // Size of the base event.
               sizeof(in_port_t) + // Source port.
               sizeof(in_port_t) + // Destination port.
               2;                  // Payload.
      }
    }
  }
}

#endif // NET_MON_EVENT_TCP_DATA_H
