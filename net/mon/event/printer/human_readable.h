#ifndef NET_MON_EVENT_PRINTER_HUMAN_READABLE_H
#define NET_MON_EVENT_PRINTER_HUMAN_READABLE_H

#include <inttypes.h>
#include "net/mon/event/printer/base.h"
#include "net/mon/event/printer/format.h"

namespace net {
  namespace mon {
    namespace event {
      namespace printer {
        // Human readable printer.
        class human_readable : public base {
          public:
            // Constructor.
            human_readable(format fmt = format::pretty_print);

            // Print 'ICMP' event.
            void print(uint64_t nevent,
                       const event::icmp& ev,
                       const char* srchost,
                       const char* dsthost) final;

            // Print 'UDP' event.
            void print(uint64_t nevent,
                       const event::udp& ev,
                       const char* srchost,
                       const char* dsthost) final;

            // Print 'DNS' event.
            void print(uint64_t nevent,
                       const event::dns& ev,
                       const char* srchost,
                       const char* dsthost) final;

            // Print 'Begin TCP connection' event.
            void print(uint64_t nevent,
                       const event::tcp_begin& ev,
                       const char* srchost,
                       const char* dsthost) final;

            // Print 'TCP data' event.
            void print(uint64_t nevent,
                       const event::tcp_data& ev,
                       const char* srchost,
                       const char* dsthost) final;

            // Print 'End TCP connection' event.
            void print(uint64_t nevent,
                       const event::tcp_end& ev,
                       const char* srchost,
                       const char* dsthost) final;

          private:
            // Print format.
            format _M_format;

            // Print generic event.
            template<typename Event>
            void print_(uint64_t nevent,
                        const Event& ev,
                        const char* srchost,
                        const char* dsthost) const;
        };

        inline human_readable::human_readable(format fmt)
          : _M_format(fmt)
        {
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::icmp& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::udp& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::dns& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::tcp_begin& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::tcp_data& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void human_readable::print(uint64_t nevent,
                                          const event::tcp_end& ev,
                                          const char* srchost,
                                          const char* dsthost)
        {
          print_(nevent, ev, srchost, dsthost);
        }

        template<typename Event>
        inline void human_readable::print_(uint64_t nevent,
                                           const Event& ev,
                                           const char* srchost,
                                           const char* dsthost) const
        {
          if (_M_format == format::pretty_print) {
            fprintf(_M_file, "Event: %" PRIu64 "\n", nevent);
          } else {
            fprintf(_M_file, "[#%" PRIu64 "] ", nevent);
          }

          ev.print_human_readable(_M_file, _M_format, srchost, dsthost);
          fprintf(_M_file, "\n");
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_PRINTER_HUMAN_READABLE_H
