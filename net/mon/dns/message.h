#ifndef NET_MON_DNS_MESSAGE_H
#define NET_MON_DNS_MESSAGE_H

#include <stdint.h>
#include <sys/types.h>
#include "net/mon/event/dns.h"

namespace net {
  namespace mon {
    namespace dns {
      // DNS port in network byte order.
      static constexpr const uint16_t port = static_cast<uint16_t>(53) << 8;

      class message {
        public:
          // Constructor.
          message(const void* buf, size_t len);

          // Destructor.
          ~message() = default;

          // Parse DNS message.
          bool parse(event::dns& ev);

        private:
          // Maximum length of a DNS message.
          static constexpr const size_t max_len = 512;

          // Length of the DNS header.
          static constexpr const size_t header_len = 12;

          // Maximum number of DNS pointers.
          static constexpr const size_t max_pointers = 64;

          // Message buffer.
          const uint8_t* const _M_buf;

          // Message length.
          const size_t _M_len;

          // Current offset.
          size_t _M_off;

          // Skip question.
          bool skip_question();

          // Parse domain-name.
          bool parse_domain_name(char* domain, uint8_t& domainlen);

          // Skip domain-name.
          bool skip_domain_name();
      };

      inline message::message(const void* buf, size_t len)
        : _M_buf(static_cast<const uint8_t* const>(buf)),
          _M_len(len)
      {
      }

      inline bool message::skip_question()
      {
        if ((skip_domain_name()) && (_M_off + 4 <= _M_len)) {
          _M_off += 4;

          return true;
        } else {
          return false;
        }
      }
    }
  }
}

#endif // NET_MON_DNS_MESSAGE_H
