#include "util/parser/number.h"

bool util::parser::number::parse_view(const char* s,
                                      size_t len,
                                      uint64_t& n,
                                      uint64_t min,
                                      uint64_t max)
{
  if (len > 0) {
    uint64_t res = 0;

    for (size_t i = 0; i < len; i++) {
      uint64_t tmp;
      if ((s[i] >= '0') &&
          (s[i] <= '9') &&
          ((tmp = (res * 10) + (s[i] - '0')) >= res) &&
          (tmp <= max)) {
        res = tmp;
      } else {
        return false;
      }
    }

    if (res >= min) {
      n = res;
      return true;
    }
  }

  return false;
}
