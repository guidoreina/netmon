#ifndef NET_MON_TCP_PORT_PAIR_H
#define NET_MON_TCP_PORT_PAIR_H

#include <stdint.h>
#include <netinet/in.h>

namespace net {
  namespace mon {
    namespace tcp {
      struct port_pair {
        union {
          uint32_t ports;

          struct {
            in_port_t port2;
            in_port_t port1;
          } p;
        };

        // Constructor.
        port_pair() = default;
        port_pair(in_port_t port1, in_port_t port2);

        // Assign.
        void assign(in_port_t port1, in_port_t port2);

        // Equal operator.
        bool operator==(port_pair other) const;
      };

      inline port_pair::port_pair(in_port_t port1, in_port_t port2)
      {
        assign(port1, port2);
      }

      inline void port_pair::assign(in_port_t port1, in_port_t port2)
      {
        ports = (static_cast<uint32_t>(port1) << 16) | port2;
      }

      inline bool port_pair::operator==(port_pair other) const
      {
        return (ports == other.ports);
      }
    }
  }
}

#endif // NET_MON_TCP_PORT_PAIR_H
