#ifndef UTIL_HASH_H
#define UTIL_HASH_H

#include <stdint.h>
#include <sys/types.h>

namespace util {
  class hash {
    public:
      // Hash functions by Bob Jenkins:
      // http://burtleburtle.net/bob/c/lookup3.c

      // Hash 1 word.
      static uint32_t hash_1word(uint32_t a, uint32_t initval);

      // Hash 2 words.
      static uint32_t hash_2words(uint32_t a, uint32_t b, uint32_t initval);

      // Hash 3 words.
      static uint32_t hash_3words(uint32_t a,
                                  uint32_t b,
                                  uint32_t c,
                                  uint32_t initval);

      // Hash a variable-length key into a 32-bit value.
      static uint32_t hashlittle(const void* key,
                                 size_t length,
                                 uint32_t initval);

    private:
      static constexpr const uint32_t hash_initval = 0xdeadbeef;

      // Hash n words (n can be 1, 2 or 3).
      static uint32_t hash_nwords(uint32_t a,
                                   uint32_t b,
                                   uint32_t c,
                                   uint32_t initval);

      static uint32_t rol32(uint32_t x, uint32_t k);
      static uint32_t get_unaligned_cpu32(const void* p);
  };

  #define hash_mix(a, b, c) {         \
    a -= c; a ^= rol32(c, 4);  c += b; \
    b -= a; b ^= rol32(a, 6);  a += c; \
    c -= b; c ^= rol32(b, 8);  b += a; \
    a -= c; a ^= rol32(c, 16); c += b; \
    b -= a; b ^= rol32(a, 19); a += c; \
    c -= b; c ^= rol32(b, 4);  b += a; \
  }

  #define hash_final(a, b, c) {   \
    c ^= b; c -= rol32(b, 14);     \
    a ^= c; a -= rol32(c, 11);     \
    b ^= a; b -= rol32(a, 25);     \
    c ^= b; c -= rol32(b, 16);     \
    a ^= c; a -= rol32(c, 4);      \
    b ^= a; b -= rol32(a, 14);     \
    c ^= b; c -= rol32(b, 24);     \
  }

  inline uint32_t hash::hash_1word(uint32_t a, uint32_t initval)
  {
    return hash_nwords(a, 0, 0, initval + hash_initval + (1 << 2));
  }

  inline uint32_t hash::hash_2words(uint32_t a, uint32_t b, uint32_t initval)
  {
    return hash_nwords(a, b, 0, initval + hash_initval + (2 << 2));
  }

  inline uint32_t hash::hash_3words(uint32_t a,
                                    uint32_t b,
                                    uint32_t c,
                                    uint32_t initval)
  {
    return hash_nwords(a, b, c, initval + hash_initval + (3 << 2));
  }

  inline uint32_t hash::hash_nwords(uint32_t a,
                                    uint32_t b,
                                    uint32_t c,
                                    uint32_t initval)
  {
    a += initval;
    b += initval;
    c += initval;

    hash_final(a, b, c);

    return c;
  }

  inline uint32_t hash::rol32(uint32_t x, uint32_t k)
  {
    return ((x << k) | (x >> ((-k) & 31)));
  }

  inline uint32_t hash::get_unaligned_cpu32(const void* p)
  {
    struct __una_u32 {
      uint32_t x;
    } __attribute__((packed));

    return static_cast<const struct __una_u32*>(p)->x;
  }
}

#endif // UTIL_HASH_H
