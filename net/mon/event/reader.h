#ifndef NET_MON_EVENT_READER_H
#define NET_MON_EVENT_READER_H

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include "net/mon/event/events.h"
#include "net/mon/event/file.h"
#include "net/mon/event/printer/base.h"
#include "net/mon/event/grammar/expressions.h"
#include "net/mon/dns/inverted_cache.h"
#include "net/mon/ipv4/address.h"
#include "net/mon/ipv6/address.h"

namespace net {
  namespace mon {
    namespace event {
      // Event reader.
      class reader {
        public:
          // Constructor.
          reader() = default;
          reader(printer::base* printer);

          // Destructor.
          ~reader();

          // Open event file.
          bool open(const char* filename);

          // Close event file.
          void close();

          // Get next event.
          bool next(const grammar::conditional_expression* expr = nullptr);

          // Get next event.
          bool next(const void*& event, size_t& len, uint64_t& timestamp);

          // Get timestamp of the first event.
          uint64_t first_timestamp() const;

          // Get timestamp of the last event.
          uint64_t last_timestamp() const;

        private:
          int _M_fd = -1;

          void* _M_base = MAP_FAILED;

          // Size of the file.
          size_t _M_filesize;

          // Pointer to the end.
          const uint8_t* _M_end;

          // Pointer to the next event.
          const uint8_t* _M_ptr;

          // Event file header.
          file::header _M_header;

          // Printer.
          printer::base* _M_printer = nullptr;

          // Event number.
          uint64_t _M_nevent = 0;

          // IPv4 DNS cache.
          mon::dns::inverted_cache<ipv4::address> _M_ipv4_dns_cache;

          // IPv6 DNS cache.
          mon::dns::inverted_cache<ipv6::address> _M_ipv6_dns_cache;

          // Get source host.
          template<typename Event>
          const char* source_host(const Event& ev) const;

          // Get destination host.
          template<typename Event>
          const char* destination_host(const Event& ev) const;

          // Get host.
          const char* host(const void* addr, size_t addrlen) const;

          // Disable copy constructor and assignment operator.
          reader(const reader&) = delete;
          reader& operator=(const reader&) = delete;
      };

      inline reader::reader(printer::base* printer)
        : _M_printer(printer)
      {
      }

      inline reader::~reader()
      {
        close();
      }

      inline void reader::close()
      {
        if (_M_base != MAP_FAILED) {
          munmap(_M_base, _M_filesize);
          _M_base = MAP_FAILED;
        }

        if (_M_fd != -1) {
          ::close(_M_fd);
          _M_fd = -1;
        }
      }

      inline uint64_t reader::first_timestamp() const
      {
        return _M_header.timestamp.first;
      }

      inline uint64_t reader::last_timestamp() const
      {
        return _M_header.timestamp.last;
      }

      template<typename Event>
      inline const char* reader::source_host(const Event& ev) const
      {
        return host(ev.saddr, ev.addrlen);
      }

      template<typename Event>
      inline const char* reader::destination_host(const Event& ev) const
      {
        return host(ev.daddr, ev.addrlen);
      }

      inline const char* reader::host(const void* addr, size_t addrlen) const
      {
        if (addrlen == 4) {
          ipv4::address address(addr);
          return _M_ipv4_dns_cache.host(address);
        } else {
          ipv6::address address(addr);
          return _M_ipv6_dns_cache.host(address);
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_READER_H
