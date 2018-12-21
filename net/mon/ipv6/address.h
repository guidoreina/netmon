#ifndef NET_MON_IPV6_ADDRESS_H
#define NET_MON_IPV6_ADDRESS_H

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "util/hash.h"

namespace net {
  namespace mon {
    namespace ipv6 {
      struct address : public in6_addr {
        // Constructor.
        address() = default;
        address(const void* addr);

        // Equal operator.
        bool operator==(const struct in6_addr& other) const;

        // Compare.
        int compare(const struct in6_addr& other) const;

        // Hash.
        uint32_t hash() const;
      };

      struct address_pair {
        struct {
          address address2;
          address address1;
        } a;

        // Constructor.
        address_pair() = default;
        address_pair(const struct in6_addr& addr1,
                     const struct in6_addr& addr2);

        // Assign.
        void assign(const struct in6_addr& addr1, const struct in6_addr& addr2);

        // Equal operator.
        bool operator==(const address_pair& other) const;
      };

      inline address::address(const void* addr)
      {
        memcpy(s6_addr32, addr, sizeof(s6_addr32));
      }

      inline bool address::operator==(const struct in6_addr& other) const
      {
        return (((s6_addr32[0] ^ other.s6_addr32[0]) |
                 (s6_addr32[1] ^ other.s6_addr32[1]) |
                 (s6_addr32[2] ^ other.s6_addr32[2]) |
                 (s6_addr32[3] ^ other.s6_addr32[3])) == 0);
      }

      inline int address::compare(const struct in6_addr& other) const
      {
        return memcmp(s6_addr32, other.s6_addr32, sizeof(struct in6_addr));
      }

      inline uint32_t address::hash() const
      {
        static constexpr const uint32_t initval = 0;

        return util::hash::hash_3words(s6_addr32[0] ^ s6_addr32[1],
                                       s6_addr32[2],
                                       s6_addr32[3],
                                       initval);
      }

      inline address_pair::address_pair(const struct in6_addr& addr1,
                                        const struct in6_addr& addr2)
      {
        assign(addr1, addr2);
      }

      inline void address_pair::assign(const struct in6_addr& addr1,
                                       const struct in6_addr& addr2)
      {
        a.address1.s6_addr32[0] = addr1.s6_addr32[0];
        a.address1.s6_addr32[1] = addr1.s6_addr32[1];
        a.address1.s6_addr32[2] = addr1.s6_addr32[2];
        a.address1.s6_addr32[3] = addr1.s6_addr32[3];

        a.address2.s6_addr32[0] = addr2.s6_addr32[0];
        a.address2.s6_addr32[1] = addr2.s6_addr32[1];
        a.address2.s6_addr32[2] = addr2.s6_addr32[2];
        a.address2.s6_addr32[3] = addr2.s6_addr32[3];
      }

      inline bool address_pair::operator==(const address_pair& other) const
      {
        return ((a.address1 == other.a.address1) &&
                (a.address2 == other.a.address2));
      }
    }
  }
}

#endif // NET_MON_IPV6_ADDRESS_H
