#ifndef UTIL_PARSER_NUMBER_H
#define UTIL_PARSER_NUMBER_H

#include <stdint.h>
#include <string.h>
#include <limits.h>

namespace util {
  namespace parser {
    class number {
      public:
        // Parse number.
        static bool parse(const char* s,
                          uint64_t& n,
                          uint64_t min = 0,
                          uint64_t max = ULLONG_MAX);

        static bool parse_view(const char* s,
                               size_t len,
                               uint64_t& n,
                               uint64_t min = 0,
                               uint64_t max = ULLONG_MAX);
    };

    inline bool number::parse(const char* s,
                              uint64_t& n,
                              uint64_t min,
                              uint64_t max)
    {
      return parse_view(s, strlen(s), n, min, max);
    }
  }
}

#endif // UTIL_PARSER_NUMBER_H
