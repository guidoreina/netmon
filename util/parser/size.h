#ifndef UTIL_PARSER_SIZE_H
#define UTIL_PARSER_SIZE_H

#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>

namespace util {
  namespace parser {
    class size {
      public:
        // Parse size.
        static bool parse(const char* s,
                          uint64_t& n,
                          uint64_t min = 0,
                          uint64_t max = ULLONG_MAX);

        static bool parse_view(const char* s,
                               size_t len,
                               uint64_t& n,
                               uint64_t min = 0,
                               uint64_t max = ULLONG_MAX);

#if __WORDSIZE == 32
        // Parse size.
        static bool parse(const char* s,
                          size_t& n,
                          size_t min = 0,
                          size_t max = ULONG_MAX);

        static bool parse_view(const char* s,
                               size_t len,
                               size_t& n,
                               size_t min = 0,
                               size_t max = ULONG_MAX);
#endif // __WORDSIZE == 32
    };

    inline bool size::parse(const char* s,
                            uint64_t& n,
                            uint64_t min,
                            uint64_t max)
    {
      return parse_view(s, strlen(s), n, min, max);
    }

#if __WORDSIZE == 32
    inline bool size::parse(const char* s, size_t& n, size_t min, size_t max)
    {
      uint64_t res;
      if (parse(s,
                res,
                static_cast<uint64_t>(min),
                static_cast<uint64_t>(max))) {
        n = static_cast<size_t>(res);
        return true;
      }

      return false;
    }

    inline bool size::parse_view(const char* s,
                                 size_t len,
                                 size_t& n,
                                 size_t min,
                                 size_t max)
    {
      uint64_t res;
      if (parse_view(s,
                     len,
                     res,
                     static_cast<uint64_t>(min),
                     static_cast<uint64_t>(max))) {
        n = static_cast<size_t>(res);
        return true;
      }

      return false;
    }
#endif // __WORDSIZE == 32
  }
}

#endif // UTIL_PARSER_SIZE_H
