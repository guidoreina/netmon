#ifndef NET_MON_EVENT_DNS_H
#define NET_MON_EVENT_DNS_H

#include "net/mon/event/base.h"
#include "net/limits.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'DNS' event.
      struct dns : public base {
        static constexpr const type t = type::dns;
        static constexpr const size_t max_responses = 24;

        // Source port.
        in_port_t sport;

        // Destination port.
        in_port_t dport;

        // # of bytes transferred.
        uint16_t transferred;

        // Query type.
        uint8_t qtype;

        // Domain length.
        uint8_t domainlen;

        // Domain.
        char domain[domain_name_max_len];

        struct response {
          uint8_t addrlen;
          address addr;
        };

        // # of DNS responses.
        uint8_t nresponses;

        // DNS responses.
        response responses[max_responses];

        // Build 'DNS' event.
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

      static_assert(sizeof(evlen_t) + sizeof(type) + sizeof(dns) <= maxlen,
                    "'maxlen' is smaller than sizeof(dns)");

      inline size_t dns::size() const
      {
        size_t s = base::size()      + // Size of the base event.
                   sizeof(in_port_t) + // Source port.
                   sizeof(in_port_t) + // Destination port.
                   2                 + // Transferred.
                   1                 + // Query type.
                   1                 + // Domain length.
                   domainlen         + // Domain.
                   1;                  // Number of responses.

        for (size_t i = 0; i < nresponses; i++) {
          s += (1                    + // Address length.
                responses[i].addrlen); // Response.
        }

        return s;
      }
    }
  }
}

#endif // NET_MON_EVENT_DNS_H
