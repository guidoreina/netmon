#ifndef NET_MON_EVENT_PRINTER_CSV_H
#define NET_MON_EVENT_PRINTER_CSV_H

#include <inttypes.h>
#include "net/mon/event/printer/base.h"

namespace net {
  namespace mon {
    namespace event {
      namespace printer {
        // CSV printer.
        class csv : public base {
          public:
            // Default CSV separator.
            static constexpr const char default_separator = ',';

            // Constructor.
            csv(char separator = default_separator);

            // Print 'ICMP' event.
            void print(uint64_t nevent,
                       const event::icmp& ev,
                       const char* srchost,
                       const char* dsthost) const final;

            // Print 'UDP' event.
            void print(uint64_t nevent,
                       const event::udp& ev,
                       const char* srchost,
                       const char* dsthost) const final;

            // Print 'DNS' event.
            void print(uint64_t nevent,
                       const event::dns& ev,
                       const char* srchost,
                       const char* dsthost) const final;

            // Print 'Begin TCP connection' event.
            void print(uint64_t nevent,
                       const event::tcp_begin& ev,
                       const char* srchost,
                       const char* dsthost) const final;

            // Print 'TCP data' event.
            void print(uint64_t nevent,
                       const event::tcp_data& ev,
                       const char* srchost,
                       const char* dsthost) const final;

            // Print 'End TCP connection' event.
            void print(uint64_t nevent,
                       const event::tcp_end& ev,
                       const char* srchost,
                       const char* dsthost) const final;

          private:
            // CSV separator.
            char _M_separator;

            // Print generic event.
            template<typename Event>
            void print_(uint64_t nevent,
                        const Event& ev,
                        const char* srchost,
                        const char* dsthost) const;
        };

        inline csv::csv(char separator)
          : _M_separator(separator)
        {
        }

        inline void csv::print(uint64_t nevent,
                               const event::icmp& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void csv::print(uint64_t nevent,
                               const event::udp& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void csv::print(uint64_t nevent,
                               const event::dns& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void csv::print(uint64_t nevent,
                               const event::tcp_begin& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void csv::print(uint64_t nevent,
                               const event::tcp_data& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void csv::print(uint64_t nevent,
                               const event::tcp_end& ev,
                               const char* srchost,
                               const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        template<typename Event>
        inline void csv::print_(uint64_t nevent,
                                const Event& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          fprintf(_M_file, "%" PRIu64 "%c", nevent, _M_separator);
          ev.print_csv(_M_file, _M_separator, srchost, dsthost);
          fprintf(_M_file, "\n");
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_PRINTER_CSV_H
