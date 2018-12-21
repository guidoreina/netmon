#ifndef NET_MON_EVENT_PRINTER_JSON_H
#define NET_MON_EVENT_PRINTER_JSON_H

#include <inttypes.h>
#include "net/mon/event/printer/base.h"
#include "net/mon/event/printer/format.h"

namespace net {
  namespace mon {
    namespace event {
      namespace printer {
        // JSON printer.
        class json : public base {
          public:
            // Constructor.
            json(format fmt = format::pretty_print);

            // Destructor.
            ~json();

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
            // Print format.
            format _M_format;

            // Print generic event.
            template<typename Event>
            void print_(uint64_t nevent,
                        const Event& ev,
                        const char* srchost,
                        const char* dsthost) const;
        };

        inline json::json(format fmt)
          : _M_format(fmt)
        {
        }

        inline json::~json()
        {
          if (_M_file) {
            if (_M_format == format::pretty_print) {
              fprintf(_M_file, "\n]\n");
            } else {
              fprintf(_M_file, "]");
            }
          }
        }

        inline void json::print(uint64_t nevent,
                                const event::icmp& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void json::print(uint64_t nevent,
                                const event::udp& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void json::print(uint64_t nevent,
                                const event::dns& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void json::print(uint64_t nevent,
                                const event::tcp_begin& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void json::print(uint64_t nevent,
                                const event::tcp_data& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        inline void json::print(uint64_t nevent,
                                const event::tcp_end& ev,
                                const char* srchost,
                                const char* dsthost) const
        {
          print_(nevent, ev, srchost, dsthost);
        }

        template<typename Event>
        inline void json::print_(uint64_t nevent,
                                 const Event& ev,
                                 const char* srchost,
                                 const char* dsthost) const
        {
          if (_M_format == format::pretty_print) {
            fprintf(_M_file, "%c\n  {\n", (nevent > 1) ? ',' : '[');
            fprintf(_M_file, "    \"event-number\": %" PRIu64 ",\n", nevent);
          } else {
            fprintf(_M_file, "%c{", (nevent > 1) ? ',' : '[');
            fprintf(_M_file, "\"event-number\":%" PRIu64 ",", nevent);
          }

          ev.print_json(_M_file, _M_format, srchost, dsthost);

          fprintf(_M_file,
                  "%s}",
                  (_M_format == format::pretty_print) ? "  " : "");
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_PRINTER_JSON_H
