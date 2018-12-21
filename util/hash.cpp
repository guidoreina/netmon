#include "util/hash.h"

uint32_t util::hash::hashlittle(const void* key,
                                size_t length,
                                uint32_t initval)
{
  uint32_t a, b, c; // Internal state.

  // Set up the internal state.
  a = b = c = hash_initval + static_cast<uint32_t>(length) + initval;

  const uint8_t* k = static_cast<const uint8_t*>(key);

  // All but last block: aligned reads and affect 32 bits of (a, b, c).
  while (length > 12) {
    a += get_unaligned_cpu32(k);
    b += get_unaligned_cpu32(k + 4);
    c += get_unaligned_cpu32(k + 8);

    hash_mix(a, b, c);

    length -= 12;

    k += 12;
  }

  switch (length) {
    case 12: c += static_cast<uint32_t>(k[11]) << 24; // Fall through.
    case 11: c += static_cast<uint32_t>(k[10]) << 16; // Fall through.
    case 10: c += static_cast<uint32_t>(k[9]) << 8; // Fall through.
    case 9: c += k[8]; // Fall through.
    case 8: c += static_cast<uint32_t>(k[7]) << 24; // Fall through.
    case 7: c += static_cast<uint32_t>(k[6]) << 16; // Fall through.
    case 6: c += static_cast<uint32_t>(k[5]) << 8; // Fall through.
    case 5: c += k[4]; // Fall through.
    case 4: c += static_cast<uint32_t>(k[3]) << 24; // Fall through.
    case 3: c += static_cast<uint32_t>(k[2]) << 16; // Fall through.
    case 2: c += static_cast<uint32_t>(k[1]) << 8; // Fall through.
    case 1:
      c += k[0];

      hash_final(a, b, c);
      break;
  }

  return c;
}
