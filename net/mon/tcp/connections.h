#ifndef NET_MON_TCP_CONNECTIONS_H
#define NET_MON_TCP_CONNECTIONS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "net/mon/tcp/connection.h"
#include "net/mon/event/writer.h"
#include "util/hash.h"

namespace net {
  namespace mon {
    namespace tcp {
      // Connection hash table.
      template<typename Connection>
      class connections {
        public:
          // Minimum size of the hash table (256).
          static constexpr const size_t min_size = static_cast<size_t>(1) << 8;

          // Maximum size of the hash table (4294967296 [64bit], 65536 [32bit]).
          static constexpr const size_t
                 max_size = static_cast<size_t>(1) << (4 * sizeof(size_t));

          // Default size of the hash table (4096).
          static constexpr const size_t
                 default_size = static_cast<size_t>(1) << 12;

          // Minimum number of connections.
          static constexpr const size_t min_connections = min_size;

          // Maximum number of connections.
          static constexpr const size_t max_connections = max_size;

          // Maximum number of connections (default) (1048576).
          static constexpr const size_t
                 default_max_connections = static_cast<size_t>(1) << 20;

          // Minimum connection timeout (seconds).
          static constexpr const uint64_t min_timeout = 5;

          // Default connection timeout (seconds).
          static constexpr const uint64_t default_timeout = 2 * 3600;

          // Minimum TCP time wait (seconds).
          static constexpr const uint64_t min_time_wait = 1;

          // Default TCP time wait (seconds).
          static constexpr const uint64_t default_time_wait = 2 * 60;

          typedef Connection connection_type;
          typedef typename connection_type::address_type address_type;

          // Constructor.
          connections(event::writer& evwriter);

          // Destructor.
          ~connections();

          // Clear.
          void clear();

          // Initialize.
          bool init(size_t size,
                    size_t maxconns,
                    uint64_t timeout,
                    uint64_t time_wait);

          // Add.
          bool add(const address_type& saddr,
                   in_port_t sport,
                   const address_type& daddr,
                   in_port_t dport,
                   uint8_t tcpflags,
                   uint16_t pktsize,
                   uint16_t payload_size,
                   uint64_t now);

          // Remove expired connections.
          void remove_expired(uint64_t now);

        private:
          static constexpr const size_t connection_allocation = 1024;

          // Connection hash table.
          util::node* _M_conns = nullptr;

          // Size of the hash table.
          size_t _M_size = 0;

          // Mask (for performing modulo).
          size_t _M_mask;

          // Maximum number of connections.
          size_t _M_max_connections;

          // Number of connections.
          size_t _M_nconnections = 0;

          // Free connections.
          connection_type* _M_free = nullptr;

          // Connection timeout.
          uint64_t _M_timeout;

          // Time wait.
          uint64_t _M_time_wait;

          // Event writer.
          event::writer& _M_evwriter;

          // Erase connections.
          static void erase(util::node* header);

          // Get free connection.
          connection_type* get_free_connection();

          // Allocate connections.
          bool allocate_connections(size_t count);

          // Add.
          bool add(const address_type& addr1,
                   in_port_t port1,
                   const address_type& addr2,
                   in_port_t port2,
                   uint8_t tcpflags,
                   uint16_t pktsize,
                   uint16_t payload_size,
                   connection::direction dir,
                   uint64_t now);

          // Remove connection.
          void remove(connection_type* conn, uint64_t now);

          // Generate 'Begin TCP connection' event.
          void event_tcp_begin(const connection_type* conn, uint64_t now);

          // Generate 'TCP data' event.
          void event_tcp_data(const address_type& addr1,
                              in_port_t port1,
                              const address_type& addr2,
                              in_port_t port2,
                              uint16_t payload_size,
                              connection::direction dir,
                              uint64_t now,
                              uint64_t creation);

          // Generate 'End TCP connection' event.
          void event_tcp_end(const connection_type* conn, uint64_t now);

          // Disable copy constructor and assignment operator.
          connections(const connections&) = delete;
          connections& operator=(const connections&) = delete;
      };

      template<typename Connection>
      inline connections<Connection>::connections(event::writer& evwriter)
        : _M_evwriter(evwriter)
      {
      }

      template<typename Connection>
      inline connections<Connection>::~connections()
      {
        clear();
      }

      template<typename Connection>
      void connections<Connection>::clear()
      {
        if (_M_conns) {
          for (size_t i = 0; i < _M_size; i++) {
            erase(&_M_conns[i]);
          }

          free(_M_conns);
          _M_conns = nullptr;
        }

        _M_size = 0;
        _M_nconnections = 0;

        while (_M_free) {
          connection_type* next = static_cast<connection_type*>(_M_free->next);

          free(_M_free);

          _M_free = next;
        }
      }

      template<typename Connection>
      bool connections<Connection>::init(size_t size,
                                         size_t maxconns,
                                         uint64_t timeout,
                                         uint64_t time_wait)
      {
        if ((size >= min_size) &&
            (size <= max_size) &&
            ((size & (size - 1)) == 0) &&
            (maxconns >= min_connections) &&
            (maxconns <= max_connections) &&
            (timeout >= min_timeout) &&
            (time_wait >= min_time_wait)) {
          // Allocate memory for the connections.
          if ((_M_conns = static_cast<util::node*>(
                            malloc(size * sizeof(util::node))
                          )) != nullptr) {
            for (size_t i = 0; i < size; i++) {
              _M_conns[i].prev = &_M_conns[i];
              _M_conns[i].next = &_M_conns[i];
            }

            _M_max_connections = maxconns;

            // Allocate free connections.
            if (allocate_connections(connection_allocation)) {
              _M_size = size;
              _M_mask = size - 1;

              _M_timeout = timeout * 1000000ull;
              _M_time_wait = time_wait * 1000000ull;

              return true;
            }
          }
        }

        return false;
      }

      template<typename Connection>
      inline bool connections<Connection>::add(const address_type& saddr,
                                               in_port_t sport,
                                               const address_type& daddr,
                                               in_port_t dport,
                                               uint8_t tcpflags,
                                               uint16_t pktsize,
                                               uint16_t payload_size,
                                               uint64_t now)
      {
        if (sport < dport) {
          return add(saddr,
                     sport,
                     daddr,
                     dport,
                     tcpflags,
                     pktsize,
                     payload_size,
                     connection::direction::from_addr1,
                     now);
        } else if (sport > dport) {
          return add(daddr,
                     dport,
                     saddr,
                     sport,
                     tcpflags,
                     pktsize,
                     payload_size,
                     connection::direction::from_addr2,
                     now);
        } else {
          int diff;
          if ((diff = saddr.compare(daddr)) <= 0) {
            return add(saddr,
                       sport,
                       daddr,
                       dport,
                       tcpflags,
                       pktsize,
                       payload_size,
                       connection::direction::from_addr1,
                       now);
          } else {
            return add(daddr,
                       dport,
                       saddr,
                       sport,
                       tcpflags,
                       pktsize,
                       payload_size,
                       connection::direction::from_addr2,
                       now);
          }
        }
      }

      template<typename Connection>
      void connections<Connection>::remove_expired(uint64_t now)
      {
        for (size_t i = 0; i < _M_size; i++) {
          util::node* header = &_M_conns[i];
          connection_type* conn = static_cast<connection_type*>(header->next);

          while (static_cast<util::node*>(conn) != header) {
            // If the connection has not been closed...
            if (conn->s != connection::state::closed) {
              // If the connection has not expired...
              if (conn->timestamp.last_packet + _M_timeout > now) {
                conn = static_cast<connection_type*>(conn->next);
              } else {
                connection_type* next =
                                 static_cast<connection_type*>(conn->next);

                remove(conn, now);

                conn = next;
              }
            } else if (conn->timestamp.last_packet + _M_time_wait >
                       now) {
              conn = static_cast<connection_type*>(conn->next);
            } else {
              connection_type* next = static_cast<connection_type*>(conn->next);

              remove(conn, now);

              conn = next;
            }
          }
        }
      }

      template<typename Connection>
      inline void connections<Connection>::erase(util::node* header)
      {
        util::node* n = header->next;

        while (n != header) {
          util::node* next = n->next;

          free(n);

          n = next;
        }
      }

      template<typename Connection>
      inline typename connections<Connection>::connection_type*
      connections<Connection>::get_free_connection()
      {
        if ((_M_free) || (allocate_connections(connection_allocation))) {
          connection_type* conn = _M_free;

          _M_free = static_cast<connection_type*>(_M_free->next);

          return conn;
        }

        return nullptr;
      }

      template<typename Connection>
      bool connections<Connection>::allocate_connections(size_t count)
      {
        size_t diff;
        if ((diff = _M_max_connections - _M_nconnections) > 0) {
          if (diff < count) {
            count = diff;
          }

          for (size_t i = 0; i < count; i++) {
            connection_type* conn;
            if ((conn = static_cast<connection_type*>(
                          malloc(sizeof(connection_type))
                        )) != nullptr) {
              conn->next = _M_free;
              _M_free = conn;
            } else {
              return (_M_free != nullptr);
            }
          }

          return true;
        }

        return false;
      }

      template<typename Connection>
      bool connections<Connection>::add(const address_type& addr1,
                                        in_port_t port1,
                                        const address_type& addr2,
                                        in_port_t port2,
                                        uint8_t tcpflags,
                                        uint16_t pktsize,
                                        uint16_t payload_size,
                                        connection::direction dir,
                                        uint64_t now)
      {
        static constexpr const uint32_t initval = 0;

        uint32_t bucket = util::hash::hash_3words(
                            addr1.hash(),
                            addr2.hash(),
                            (static_cast<uint32_t>(port1) << 16) | port2,
                            initval
                          ) & _M_mask;

        // Search connection.
        util::node* header = &_M_conns[bucket];
        connection_type* conn = static_cast<connection_type*>(header->next);

        connection_type c(addr1, port1, addr2, port2);

        while (static_cast<util::node*>(conn) != header) {
          // If the connection has not been closed...
          if (conn->s != connection::state::closed) {
            // If the connection has not expired...
            if (conn->timestamp.last_packet + _M_timeout > now) {
              // If it is the connection we are looking for...
              if (c == *conn) {
                if (conn->process_packet(dir, tcpflags, pktsize, now)) {
                  // If there is payload...
                  if (payload_size > 0) {
                    // Generate 'TCP data' event.
                    event_tcp_data(addr1,
                                   port1,
                                   addr2,
                                   port2,
                                   payload_size,
                                   dir,
                                   now,
                                   conn->timestamp.creation);
                  }

                  return true;
                }

                connection_type* next =
                                   static_cast<connection_type*>(conn->next);

                remove(conn, now);

                conn = next;

                // Ignore invalid packet.
                return true;
              } else {
                conn = static_cast<connection_type*>(conn->next);
              }
            } else {
              connection_type* next = static_cast<connection_type*>(conn->next);

              remove(conn, now);

              conn = next;
            }
          } else if (conn->timestamp.last_packet + _M_time_wait >
                     now) {
            conn = static_cast<connection_type*>(conn->next);
          } else {
            connection_type* next = static_cast<connection_type*>(conn->next);

            remove(conn, now);

            conn = next;
          }
        }

        // Connection not found.

        // SYN?
        if ((tcpflags & connection::flag_mask) == connection::syn) {
          if ((conn = get_free_connection()) != nullptr) {
            conn->prev = header;
            conn->next = header->next;

            header->next->prev = conn;
            header->next = conn;

            conn->assign(addr1, port1, addr2, port2);

            conn->init(dir, pktsize, now);

            // Generate 'Begin TCP connection' event.
            event_tcp_begin(conn, now);

            _M_nconnections++;
          } else {
            return false;
          }
        }

        return true;
      }

      template<typename Connection>
      inline void connections<Connection>::remove(connection_type* conn,
                                                  uint64_t now)
      {
        // Generate 'End TCP connection' event.
        event_tcp_end(conn, now);

        // Remove connection.
        conn->prev->next = conn->next;
        conn->next->prev = conn->prev;

        conn->next = _M_free;
        _M_free = conn;

        _M_nconnections--;
      }

      template<typename Connection>
      void connections<Connection>::event_tcp_begin(const connection_type* conn,
                                                    uint64_t now)
      {
        event::tcp_begin ev;

        ev.addrlen = static_cast<uint8_t>(sizeof(address_type));

        // If 'addr2' is the client...
        if (conn->active_opener == connection::originator::addr2) {
          memcpy(ev.saddr, &conn->addresses().a.address2, sizeof(address_type));
          memcpy(ev.daddr, &conn->addresses().a.address1, sizeof(address_type));

          ev.sport = conn->ports().p.port2;
          ev.dport = conn->ports().p.port1;
        } else {
          memcpy(ev.saddr, &conn->addresses().a.address1, sizeof(address_type));
          memcpy(ev.daddr, &conn->addresses().a.address2, sizeof(address_type));

          ev.sport = conn->ports().p.port1;
          ev.dport = conn->ports().p.port2;
        }

        ev.timestamp = now;

        // Write event.
        _M_evwriter.write(ev);
      }

      template<typename Connection>
      void connections<Connection>::event_tcp_data(const address_type& addr1,
                                                   in_port_t port1,
                                                   const address_type& addr2,
                                                   in_port_t port2,
                                                   uint16_t payload_size,
                                                   connection::direction dir,
                                                   uint64_t now,
                                                   uint64_t creation)
      {
        event::tcp_data ev;

        ev.addrlen = static_cast<uint8_t>(sizeof(address_type));

        // If 'addr1' is the source...
        if (dir == connection::direction::from_addr1) {
          memcpy(ev.saddr, &addr1, sizeof(address_type));
          memcpy(ev.daddr, &addr2, sizeof(address_type));

          ev.sport = port1;
          ev.dport = port2;
        } else {
          memcpy(ev.saddr, &addr2, sizeof(address_type));
          memcpy(ev.daddr, &addr1, sizeof(address_type));

          ev.sport = port2;
          ev.dport = port1;
        }

        ev.timestamp = now;

        ev.creation = creation;

        ev.payload = payload_size;

        // Write event.
        _M_evwriter.write(ev);
      }

      template<typename Connection>
      void connections<Connection>::event_tcp_end(const connection_type* conn,
                                                  uint64_t now)
      {
        event::tcp_end ev;

        ev.addrlen = static_cast<uint8_t>(sizeof(address_type));

        // If 'addr2' is the client...
        if (conn->active_opener == connection::originator::addr2) {
          memcpy(ev.saddr, &conn->addresses().a.address2, sizeof(address_type));
          memcpy(ev.daddr, &conn->addresses().a.address1, sizeof(address_type));

          ev.sport = conn->ports().p.port2;
          ev.dport = conn->ports().p.port1;

          ev.transferred_client = conn->sent[1];
          ev.transferred_server = conn->sent[0];
        } else {
          memcpy(ev.saddr, &conn->addresses().a.address1, sizeof(address_type));
          memcpy(ev.daddr, &conn->addresses().a.address2, sizeof(address_type));

          ev.sport = conn->ports().p.port1;
          ev.dport = conn->ports().p.port2;

          ev.transferred_client = conn->sent[0];
          ev.transferred_server = conn->sent[1];
        }

        switch (conn->s) {
          case connection::state::closing:
          case connection::state::closed:
          case connection::state::failure:
            ev.timestamp = conn->timestamp.last_packet;
            break;
          default:
            ev.timestamp = now;
        }

        ev.creation = conn->timestamp.creation;

        // Write event.
        _M_evwriter.write(ev);
      }
    }
  }
}

#endif // NET_MON_TCP_CONNECTIONS_H
