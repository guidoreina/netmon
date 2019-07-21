#include "net/mask.h"
#include "util/parser/number.h"

bool net::mask::build(const char* s)
{
  const char* const slash = strchr(s, '/');

  if (!slash) {
    if (inet_pton(AF_INET, s, _M_netmask.addr32) == 1) {
      _M_type = type::ipv4;

      _M_netmask.addr32[0] = ntohl(_M_netmask.addr32[0]);
      _M_mask.addr32[0] = 0xffffffffu;

      return true;
    } else if (inet_pton(AF_INET6, s, _M_netmask.addr32) == 1) {
      _M_type = type::ipv6;

      _M_mask.addr32[0] = 0xffffffffu;
      _M_mask.addr32[1] = 0xffffffffu;
      _M_mask.addr32[2] = 0xffffffffu;
      _M_mask.addr32[3] = 0xffffffffu;

      return true;
    }
  } else {
    const size_t len = slash - s;

    // If the length is neither too short nor too long...
    if ((len > 0) && (len < INET6_ADDRSTRLEN)) {
      char ip[INET6_ADDRSTRLEN];
      memcpy(ip, s, len);
      ip[len] = 0;

      if (inet_pton(AF_INET, ip, _M_netmask.addr32) == 1) {
        uint64_t n;
        if (util::parser::number::parse(slash + 1, n, 1, 32)) {
          _M_type = type::ipv4;

          const size_t shift = 32 - static_cast<size_t>(n);

          _M_mask.addr32[0] = (0xffffffffu >> shift) << shift;

          _M_netmask.addr32[0] = ntohl(_M_netmask.addr32[0]) &
                                 _M_mask.addr32[0];

          return true;
        }
      } else if (inet_pton(AF_INET6, ip, _M_netmask.addr32) == 1) {
        uint64_t n;
        if (util::parser::number::parse(slash + 1, n, 1, 128)) {
          _M_type = type::ipv6;

          size_t idx = static_cast<size_t>(n) >> 3;

          if (idx > 0) {
            memset(_M_mask.addr8, 0xff, idx);
          }

          const size_t mod = static_cast<size_t>(n) & 0x07;

          if (mod != 0) {
            const size_t shift = 8 - mod;

            _M_mask.addr8[idx] = (static_cast<uint8_t>(0xff) >> shift) << shift;

            idx++;
          }

          if (idx < sizeof(_M_mask)) {
            memset(_M_mask.addr8 + idx, 0, sizeof(_M_mask) - idx);
          }

          _M_netmask.addr32[0] &= _M_mask.addr32[0];
          _M_netmask.addr32[1] &= _M_mask.addr32[1];
          _M_netmask.addr32[2] &= _M_mask.addr32[2];
          _M_netmask.addr32[3] &= _M_mask.addr32[3];

          return true;
        }
      }
    }
  }

  return false;
}
