#ifndef NET_MON_EVENT_FILE_H
#define NET_MON_EVENT_FILE_H

#include <stdint.h>
#include <sys/types.h>
#include "net/mon/event/util.h"

namespace net {
  namespace mon {
    namespace event {
      // Event file.
      class file {
        public:
          // Event file header.
          class header {
            public:
              // Magic number.
              static constexpr const uint64_t magic = 0x6e65746d6f6e0001;

              // Timestamp of the first and last events.
              struct {
                uint64_t first;
                uint64_t last;
              } timestamp;

              // Header size.
              static constexpr const size_t size = sizeof(magic) +
                                                   sizeof(timestamp);

              // Constructor.
              header() = default;

              // Destructor.
              ~header() = default;

              // Serialize.
              ssize_t serialize(void* buf, size_t size) const;

              // Deserialize.
              ssize_t deserialize(const void* buf, size_t size);
          };
      };

      inline ssize_t file::header::serialize(void* buf, size_t size) const
      {
        if (size >= header::size) {
          buf = event::serialize(buf, magic);
          buf = event::serialize(buf, timestamp.first);
          event::serialize(buf, timestamp.last);

          return header::size;
        }

        return -1;
      }

      inline ssize_t file::header::deserialize(const void* buf, size_t size)
      {
        uint64_t n;
        if ((size >= header::size) && (event::deserialize(n, buf) == magic)) {
          event::deserialize(timestamp.first,
                             static_cast<const uint8_t*>(buf) + sizeof(magic));

          event::deserialize(timestamp.last,
                             static_cast<const uint8_t*>(buf) +
                             sizeof(magic) +
                             8);

          return header::size;
        }

        return -1;
      }
    }
  }
}

#endif // NET_MON_EVENT_FILE_H
