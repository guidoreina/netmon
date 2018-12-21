#include "util/parser/size.h"

bool util::parser::size::parse_view(const char* s,
                                    size_t len,
                                    uint64_t& n,
                                    uint64_t min,
                                    uint64_t max)
{
  if (len > 0) {
    uint64_t res = 0;

    for (size_t i = 0; i < len; i++) {
      uint64_t tmp;
      if ((s[i] >= '0') && (s[i] <= '9')) {
        if ((tmp = (res * 10) + (s[i] - '0')) >= res) {
          res = tmp;
        } else {
          // Overflow.
          return false;
        }
      } else if ((i > 0) && (i + 1 == len)) {
        uint64_t mul;

        switch (s[i]) {
          case 'G': // GiB.
            mul = static_cast<uint64_t>(1) << 30;
            break;
          case 'M': // MiB.
            mul = static_cast<uint64_t>(1) << 20;
            break;
          case 'K': // KiB.
            mul = static_cast<uint64_t>(1) << 10;
            break;
          case 'B': // Bytes.
            mul = 1;
            break;
          default:
            return false;
        }

        if (res > 0) {
          if (((tmp = res * mul) >= res) && (tmp >= mul)) {
            res = tmp;
          } else {
            // Overflow.
            return false;
          }
        }

        break;
      } else {
        return false;
      }
    }

    if ((res >= min) && (res <= max)) {
      n = res;
      return true;
    }
  }

  return false;
}
