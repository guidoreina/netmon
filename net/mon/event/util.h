#ifndef NET_MON_EVENT_UTIL_H
#define NET_MON_EVENT_UTIL_H

#include <stdint.h>

namespace net {
  namespace mon {
    namespace event {
      static inline void* serialize(void* buf, uint8_t n)
      {
        static_cast<uint8_t*>(buf)[0] = n;

        return static_cast<uint8_t*>(buf) + sizeof(n);
      }

      static inline void* serialize(void* buf, uint16_t n)
      {
        static_cast<uint8_t*>(buf)[0] = (n >> 8) & 0xff;
        static_cast<uint8_t*>(buf)[1] = n & 0xff;

        return static_cast<uint8_t*>(buf) + sizeof(n);
      }

      static inline void* serialize(void* buf, uint32_t n)
      {
        static_cast<uint8_t*>(buf)[0] = (n >> 24) & 0xff;
        static_cast<uint8_t*>(buf)[1] = (n >> 16) & 0xff;
        static_cast<uint8_t*>(buf)[2] = (n >> 8) & 0xff;
        static_cast<uint8_t*>(buf)[3] = n & 0xff;

        return static_cast<uint8_t*>(buf) + sizeof(n);
      }

      static inline void* serialize(void* buf, uint64_t n)
      {
        static_cast<uint8_t*>(buf)[0] = (n >> 56) & 0xff;
        static_cast<uint8_t*>(buf)[1] = (n >> 48) & 0xff;
        static_cast<uint8_t*>(buf)[2] = (n >> 40) & 0xff;
        static_cast<uint8_t*>(buf)[3] = (n >> 32) & 0xff;
        static_cast<uint8_t*>(buf)[4] = (n >> 24) & 0xff;
        static_cast<uint8_t*>(buf)[5] = (n >> 16) & 0xff;
        static_cast<uint8_t*>(buf)[6] = (n >> 8) & 0xff;
        static_cast<uint8_t*>(buf)[7] = n & 0xff;

        return static_cast<uint8_t*>(buf) + sizeof(n);
      }

      static inline uint8_t deserialize(uint8_t& n, const void* buf)
      {
        n = *static_cast<const uint8_t*>(buf);
        return n;
      }

      static inline uint16_t deserialize(uint16_t& n, const void* buf)
      {
        n = (static_cast<uint16_t>(static_cast<const uint8_t*>(buf)[0]) << 8) |
             static_cast<uint16_t>(static_cast<const uint8_t*>(buf)[1]);

        return n;
      }

      static inline uint32_t deserialize(uint32_t& n, const void* buf)
      {
        n = (static_cast<uint32_t>(static_cast<const uint8_t*>(buf)[0]) << 24) |
            (static_cast<uint32_t>(static_cast<const uint8_t*>(buf)[1]) << 16) |
            (static_cast<uint32_t>(static_cast<const uint8_t*>(buf)[2]) << 8) |
             static_cast<uint32_t>(static_cast<const uint8_t*>(buf)[3]);

        return n;
      }

      static inline uint64_t deserialize(uint64_t& n, const void* buf)
      {
        n = (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[0]) << 56) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[1]) << 48) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[2]) << 40) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[3]) << 32) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[4]) << 24) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[5]) << 16) |
            (static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[6]) << 8) |
             static_cast<uint64_t>(static_cast<const uint8_t*>(buf)[7]);

        return n;
      }
    }
  }
}

#endif // NET_MON_EVENT_UTIL_H
