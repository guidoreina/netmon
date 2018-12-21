#ifndef NET_MON_IPV4_ADDRESS_H
#define NET_MON_IPV4_ADDRESS_H

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

namespace net {
  namespace mon {
    namespace ipv4 {
      struct address : public in_addr {
        // Constructor.
        address() = default;
        address(uint32_t addr);
        address(const void* addr);

        // Equal operator.
        bool operator==(struct in_addr other) const;

        // Compare.
        int compare(struct in_addr other) const;

        // Hash.
        uint32_t hash() const;
      };

      struct address_pair {
        union {
          uint64_t addresses;

          struct {
            struct in_addr address2;
            struct in_addr address1;
          } a;
        };

        // Constructor.
        address_pair() = default;
        address_pair(struct in_addr addr1, struct in_addr addr2);

        // Assign.
        void assign(struct in_addr addr1, struct in_addr addr2);

        // Equal operator.
        bool operator==(address_pair other) const;
      };

      inline address::address(uint32_t addr)
      {
        s_addr = addr;
      }

      inline address::address(const void* addr)
      {
        memcpy(&s_addr, addr, sizeof(s_addr));
      }

      inline bool address::operator==(struct in_addr other) const
      {
        return (s_addr == other.s_addr);
      }

      inline int address::compare(struct in_addr other) const
      {
        return (s_addr - other.s_addr);
      }

      inline uint32_t address::hash() const
      {
        return s_addr;
      }

      inline address_pair::address_pair(struct in_addr addr1,
                                        struct in_addr addr2)
      {
        assign(addr1, addr2);
      }

      inline void address_pair::assign(struct in_addr addr1,
                                       struct in_addr addr2)
      {
        addresses = (static_cast<uint64_t>(addr1.s_addr) << 32) | addr2.s_addr;
      }

      inline bool address_pair::operator==(address_pair other) const
      {
        return (addresses == other.addresses);
      }
    }
  }
}

#endif // NET_MON_IPV4_ADDRESS_H
