#ifndef NET_MON_EVENT_PRINTER_BASE_H
#define NET_MON_EVENT_PRINTER_BASE_H

#include <stdint.h>
#include <stdio.h>
#include "net/mon/event/events.h"

namespace net {
  namespace mon {
    namespace event {
      namespace printer {
        // Base event printer.
        class base {
          public:
            // Constructor.
            base() = default;

            // Destructor.
            virtual ~base();

            // Open.
            bool open(const char* filename);

            // Set file.
            void file(FILE* f);

            // Close.
            void close();

            // Print 'ICMP' event.
            virtual void print(uint64_t nevent,
                               const event::icmp& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

            // Print 'UDP' event.
            virtual void print(uint64_t nevent,
                               const event::udp& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

            // Print 'DNS' event.
            virtual void print(uint64_t nevent,
                               const event::dns& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

            // Print 'Begin TCP connection' event.
            virtual void print(uint64_t nevent,
                               const event::tcp_begin& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

            // Print 'TCP data' event.
            virtual void print(uint64_t nevent,
                               const event::tcp_data& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

            // Print 'End TCP connection' event.
            virtual void print(uint64_t nevent,
                               const event::tcp_end& ev,
                               const char* srchost,
                               const char* dsthost) const = 0;

          protected:
            // File.
            FILE* _M_file = nullptr;
        };

        inline base::~base()
        {
          close();
        }

        inline bool base::open(const char* filename)
        {
          return ((_M_file = fopen(filename, "w+")) != nullptr);
        }

        inline void base::file(FILE* f)
        {
          _M_file = f;
        }

        inline void base::close()
        {
          if ((_M_file) && (_M_file != stdout) && (_M_file != stderr)) {
            fclose(_M_file);
            _M_file = nullptr;
          }
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_PRINTER_BASE_H
