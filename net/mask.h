#ifndef NET_MASK_H
#define NET_MASK_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace net {
  class mask {
    public:
      // Constructor.
      mask() = default;

      // Destructor.
      ~mask() = default;

      // Build mask.
      bool build(const char* s);

      // Matches?
      bool match(const char* s) const;
      bool match(struct in_addr addr) const;
      bool match(uint32_t addr) const;
      bool match(const struct in6_addr& addr) const;
      bool match(const void* addr, size_t addrlen) const;

    private:
      enum class type {
        ipv4,
        ipv6
      };

      type _M_type;

      union address {
        uint8_t addr8[16];
        uint32_t addr32[4];
      };

      address _M_netmask;
      address _M_mask;
  };

  inline bool mask::match(const char* s) const
  {
    struct in6_addr addr;
    if (inet_pton(AF_INET, s, &addr) == 1) {
      return match(addr.s6_addr32[0]);
    } else if (inet_pton(AF_INET6, s, &addr) == 1) {
      return match(addr);
    } else {
      return false;
    }
  }

  inline bool mask::match(struct in_addr addr) const
  {
    return match(addr.s_addr);
  }

  inline bool mask::match(uint32_t addr) const
  {
    return ((_M_type == type::ipv4) &&
            ((ntohl(addr) & _M_mask.addr32[0]) == _M_netmask.addr32[0]));
  }

  inline bool mask::match(const struct in6_addr& addr) const
  {
    return ((_M_type == type::ipv6) &&
            ((addr.s6_addr32[0] & _M_mask.addr32[0]) == _M_netmask.addr32[0]) &&
            ((addr.s6_addr32[1] & _M_mask.addr32[1]) == _M_netmask.addr32[1]) &&
            ((addr.s6_addr32[2] & _M_mask.addr32[2]) == _M_netmask.addr32[2]) &&
            ((addr.s6_addr32[3] & _M_mask.addr32[3]) == _M_netmask.addr32[3]));
  }

  inline bool mask::match(const void* addr, size_t addrlen) const
  {
    switch (addrlen) {
      case sizeof(struct in_addr):
        {
          uint32_t address;
          memcpy(&address, addr, sizeof(struct in_addr));

          return match(address);
        }
      case sizeof(struct in6_addr):
        {
          struct in6_addr address;
          memcpy(&address, addr, sizeof(struct in6_addr));

          return match(address);
        }
      default:
        return false;
    }
  }
}

#endif // NET_MASK_H
