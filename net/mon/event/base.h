#ifndef NET_MON_EVENT_BASE_H
#define NET_MON_EVENT_BASE_H

#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include "net/address.h"
#include "net/mon/event/util.h"
#include "net/mon/event/printer/format.h"

namespace net {
  namespace mon {
    namespace event {
      // Event length type.
      typedef uint16_t evlen_t;

      // Event types.
      enum class type : uint8_t {
        icmp,
        udp,
        dns,
        tcp_begin,
        tcp_data,
        tcp_end
      };

      // Minimum length of an event (size of the base event for IPv4).
      static constexpr const size_t
             minlen = sizeof(evlen_t) + // Length.
                      8               + // Timestamp.
                      sizeof(type)    + // Type.
                      1               + // Address length.
                      4               + // Source address.
                      4;                // Destination address.

      // Maximum length of an event (must be greater or equal than the biggest
      // event).
      static constexpr const size_t maxlen = 1024;

      // Base event.
      struct base {
        // Number of microseconds since the Epoch,
        // 1970-01-01 00:00:00 +0000 (UTC).
        uint64_t timestamp;

        // Address length (either 4 [IPv4] or 16 [IPv6]).
        uint8_t addrlen;

        // Source address.
        address saddr;

        // Destination address.
        address daddr;

        // Extract length.
        static evlen_t extract_length(const void* buf);

        // Extract timestamp.
        static uint64_t extract_timestamp(const void* buf);

        // Extract type.
        static type extract_type(const void* buf);

        // Build event.
        bool build(const void* buf, size_t len);

        // Get size.
        size_t size() const;

        // Serialize.
        void* serialize(void* buf, type t) const;

        // Print human readable.
        void print_human_readable(FILE* file,
                                  printer::format fmt,
                                  const char* srchost,
                                  const char* dsthost) const;

        void print_human_readable(FILE* file,
                                  printer::format fmt,
                                  const char* srchost,
                                  const char* dsthost,
                                  in_port_t sport,
                                  in_port_t dport) const;

        // Print JSON.
        void print_json(FILE* file,
                        printer::format fmt,
                        const char* srchost,
                        const char* dsthost) const;

        void print_json(FILE* file,
                        printer::format fmt,
                        const char* srchost,
                        const char* dsthost,
                        in_port_t sport,
                        in_port_t dport) const;

        // Print CSV.
        void print_csv(FILE* file,
                       char separator,
                       const char* srchost,
                       const char* dsthost) const;

        void print_csv(FILE* file,
                       char separator,
                       const char* srchost,
                       const char* dsthost,
                       in_port_t sport,
                       in_port_t dport) const;
      };

      inline evlen_t base::extract_length(const void* buf)
      {
        evlen_t len;
        return event::deserialize(len, buf);
      }

      inline uint64_t base::extract_timestamp(const void* buf)
      {
        uint64_t timestamp;
        return event::deserialize(timestamp,
                                  static_cast<const uint8_t*>(buf) +
                                  sizeof(evlen_t));
      }

      inline type base::extract_type(const void* buf)
      {
        return static_cast<type>(
                 static_cast<const uint8_t*>(buf)[sizeof(evlen_t) + 8]
               );
      }

      inline size_t base::size() const
      {
        return sizeof(evlen_t) + // Length.
               8               + // Timestamp.
               sizeof(type)    + // Type.
               1               + // Address length.
               addrlen         + // Source address.
               addrlen;          // Destination address.
      }

      inline void* base::serialize(void* buf, type t) const
      {
        // Serialize timestamp, leaving space for the length.
        buf = event::serialize(static_cast<uint8_t*>(buf) + sizeof(evlen_t),
                               timestamp);

        // Serialize type.
        buf = event::serialize(buf, static_cast<uint8_t>(t));

        // Serialize address length.
        buf = event::serialize(buf, addrlen);

        // Copy source address.
        buf = static_cast<uint8_t*>(memcpy(buf, saddr, addrlen)) + addrlen;

        // Copy destination address.
        return static_cast<uint8_t*>(memcpy(buf, daddr, addrlen)) + addrlen;
      }
    }
  }
}

#endif // NET_MON_EVENT_BASE_H
