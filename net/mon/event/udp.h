#ifndef NET_MON_EVENT_UDP_H
#define NET_MON_EVENT_UDP_H

#include "net/mon/event/base.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'UDP' event.
      struct udp : public base {
        static constexpr const type t = type::udp;

        // Source port.
        in_port_t sport;

        // Destination port.
        in_port_t dport;

        // # of bytes transferred.
        uint16_t transferred;

        // Build 'UDP' event.
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

      static_assert(sizeof(evlen_t) + sizeof(type) + sizeof(udp) <= maxlen,
                    "'maxlen' is smaller than sizeof(udp)");

      inline size_t udp::size() const
      {
        return base::size()      + // Size of the base event.
               sizeof(in_port_t) + // Source port.
               sizeof(in_port_t) + // Destination port.
               2;                  // Transferred.
      }
    }
  }
}

#endif // NET_MON_EVENT_UDP_H
