#ifndef NET_MON_EVENT_PRINTER_DB_SQLITE_H
#define NET_MON_EVENT_PRINTER_DB_SQLITE_H

#include <arpa/inet.h>
#include <sqlite3.h>
#include "net/mon/event/printer/base.h"

namespace net {
  namespace mon {
    namespace event {
      namespace printer {
        namespace db {
          // SQLite database printer.
          class sqlite : public base {
            public:
              // Constructor.
              sqlite();

              // Destructor.
              ~sqlite();

              // Open.
              bool open(const char* filename);

              // Close.
              bool close();

              // Initialize.
              bool init();

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
              // SQLite database handle.
              sqlite3* _M_db = nullptr;

              // SQL statements.
              sqlite3_stmt* _M_statements[6];

              char _M_src[INET6_ADDRSTRLEN];
              char _M_dst[INET6_ADDRSTRLEN];

              // Create tables.
              bool create_tables();

              // Create indices.
              bool create_indices();

              // Prepare statements.
              bool prepare_statements();

              // Bind values.
              template<typename Event>
              bool bind(size_t idx, const Event& ev);

              // Bind values.
              template<typename Event>
              bool bind(size_t idx,
                        const Event& ev,
                        const char* srchost,
                        const char* dsthost);
          };

          inline sqlite::sqlite()
            : _M_statements{nullptr,
                            nullptr,
                            nullptr,
                            nullptr,
                            nullptr,
                            nullptr}
          {
          }

          inline sqlite::~sqlite()
          {
            // Close database.
            close();
          }

          inline bool sqlite::open(const char* filename)
          {
            // Open database.
            if (sqlite3_open(filename, &_M_db) == SQLITE_OK) {
              return true;
            }

            close();

            return false;
          }

          inline bool sqlite::init()
          {
            return ((create_tables()) &&
                    (create_indices()) &&
                    (prepare_statements()));
          }

          template<typename Event>
          bool sqlite::bind(size_t idx, const Event& ev)
          {
            if (ev.addrlen == 4) {
              if ((!inet_ntop(AF_INET, ev.saddr, _M_src, sizeof(_M_src))) ||
                  (!inet_ntop(AF_INET, ev.daddr, _M_dst, sizeof(_M_dst)))) {
                return false;
              }
            } else {
              if ((!inet_ntop(AF_INET6, ev.saddr, _M_src, sizeof(_M_src))) ||
                  (!inet_ntop(AF_INET6, ev.daddr, _M_dst, sizeof(_M_dst)))) {
                return false;
              }
            }

            return ((sqlite3_reset(_M_statements[idx]) == SQLITE_OK) &&
                    (sqlite3_clear_bindings(_M_statements[idx]) == SQLITE_OK) &&
                    (sqlite3_bind_int64(_M_statements[idx],
                                        1,
                                        ev.timestamp) == SQLITE_OK) &&
                    (sqlite3_bind_text(_M_statements[idx],
                                       2,
                                       _M_src,
                                       -1,
                                       SQLITE_STATIC) == SQLITE_OK) &&
                    (sqlite3_bind_text(_M_statements[idx],
                                       3,
                                       _M_dst,
                                       -1,
                                       SQLITE_STATIC) == SQLITE_OK));
          }

          template<typename Event>
          bool sqlite::bind(size_t idx,
                            const Event& ev,
                            const char* srchost,
                            const char* dsthost)
          {
            return ((bind(idx, ev)) &&
                    (sqlite3_bind_text(_M_statements[idx],
                                       4,
                                       srchost,
                                       -1,
                                       SQLITE_STATIC) == SQLITE_OK) &&
                    (sqlite3_bind_text(_M_statements[idx],
                                       5,
                                       dsthost,
                                       -1,
                                       SQLITE_STATIC) == SQLITE_OK));
          }
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_PRINTER_DB_SQLITE_H
