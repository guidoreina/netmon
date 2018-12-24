#ifndef NET_MON_EVENT_TCP_END_H
#define NET_MON_EVENT_TCP_END_H

#include "net/mon/event/base.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace event {
      // 'End TCP connection' event.
      struct tcp_end : public base {
        static constexpr const type t = type::tcp_end;

        // Source port.
        in_port_t sport;

        // Destination port.
        in_port_t dport;

        // Creation timestamp.
        uint64_t creation;

        // # of bytes sent by the client.
        uint64_t transferred_client;

        // # of bytes sent by the server.
        uint64_t transferred_server;

        // Build 'End TCP connection' event.
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

      static_assert(sizeof(evlen_t) + sizeof(type) + sizeof(tcp_end) <= maxlen,
                    "'maxlen' is smaller than sizeof(tcp_end)");

      inline size_t tcp_end::size() const
      {
        return base::size()      + // Size of the base event.
               sizeof(in_port_t) + // Source port.
               sizeof(in_port_t) + // Destination port.
               8                 + // Creation timestamp.
               8                 + // # of bytes sent by the client.
               8;                  // # of bytes sent by the server.
      }
    }
  }
}

#endif // NET_MON_EVENT_TCP_END_H
