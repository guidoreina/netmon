#ifndef NET_MON_EVENT_ICMP_H
#define NET_MON_EVENT_ICMP_H

#include "net/mon/event/base.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'ICMP' event.
      struct icmp : public base {
        static constexpr const type t = type::icmp;

        // ICMP type.
        uint8_t icmp_type;

        // ICMP code.
        uint8_t icmp_code;

        // # of bytes transferred.
        uint16_t transferred;

        // Build 'ICMP' event.
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

      static_assert(sizeof(evlen_t) + sizeof(type) + sizeof(icmp) <= maxlen,
                    "'maxlen' is smaller than sizeof(icmp)");

      inline size_t icmp::size() const
      {
        return base::size() + // Size of the base event.
               1            + // ICMP type.
               1            + // ICMP code.
               2;             // Transferred.
      }
    }
  }
}

#endif // NET_MON_EVENT_ICMP_H
