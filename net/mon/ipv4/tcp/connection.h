#ifndef NET_MON_IPV4_TCP_CONNECTION_H
#define NET_MON_IPV4_TCP_CONNECTION_H

#include <stdint.h>
#include "net/mon/tcp/connection.h"
#include "net/mon/ipv4/address.h"
#include "net/mon/tcp/port_pair.h"

namespace net {
  namespace mon {
    namespace ipv4 {
      namespace tcp {
        class connection : public net::mon::tcp::connection {
          public:
            typedef address address_type;

            // Constructor.
            connection() = default;
            connection(struct in_addr addr1,
                       in_port_t port1,
                       struct in_addr addr2,
                       in_port_t port2);

            // Assign.
            void assign(struct in_addr addr1,
                        in_port_t port1,
                        struct in_addr addr2,
                        in_port_t port2);

            // Equal operator.
            bool operator==(const connection& other) const;

            // Get addresses.
            const address_pair& addresses() const;

            // Get ports.
            const mon::tcp::port_pair& ports() const;

          private:
            address_pair _M_addresses;
            mon::tcp::port_pair _M_ports;

            // Disable copy constructor and assignment operator.
            connection(const connection&) = delete;
            connection& operator=(const connection&) = delete;
        };

        inline connection::connection(struct in_addr addr1,
                                      in_port_t port1,
                                      struct in_addr addr2,
                                      in_port_t port2)
        {
          assign(addr1, port1, addr2, port2);
        }

        inline void connection::assign(struct in_addr addr1,
                                       in_port_t port1,
                                       struct in_addr addr2,
                                       in_port_t port2)
        {
          _M_addresses.assign(addr1, addr2);
          _M_ports.assign(port1, port2);
        }

        inline bool connection::operator==(const connection& other) const
        {
          return ((_M_ports == other._M_ports) &&
                  (_M_addresses == other._M_addresses));
        }

        inline const address_pair& connection::addresses() const
        {
          return _M_addresses;
        }

        inline const mon::tcp::port_pair& connection::ports() const
        {
          return _M_ports;
        }
      }
    }
  }
}

#endif // NET_MON_IPV4_TCP_CONNECTION_H
