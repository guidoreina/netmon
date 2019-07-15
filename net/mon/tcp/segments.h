#ifndef NET_MON_TCP_SEGMENTS_H
#define NET_MON_TCP_SEGMENTS_H

#include <stdint.h>
#include <stdlib.h>

namespace net {
  namespace mon {
    namespace tcp {
      class segments {
        public:
          // Payload callback.
          typedef void (*payloadfn_t)(const void*, size_t, void*);

          // Gap callback.
          typedef void (*gapfn_t)(size_t, void*);

          // Constructor.
          segments() = default;

          // Destructor.
          ~segments();

          // Create.
          bool create(payloadfn_t payloadfn,
                      gapfn_t gapfn,
                      void* user = nullptr);

          // Clear.
          void clear();

          // Add segment.
          bool add(uint32_t seqno, const void* payload, size_t len);

          // FIN has been received.
          void fin();

          // Set next sequence number.
          void next_sequence_number(uint32_t seqno);

        private:
          // Maximum number of segments.
          static constexpr const size_t max_segments = 32;

          // Maximum payload size.
          static constexpr const size_t max_size = 64 * 1024;

          // Segment.
          struct segment {
            uint32_t seqno;
            void* payload;
            size_t len;

            ssize_t prev;
            ssize_t next;
          };

          // Segments.
          segment _M_segments[max_segments];

          // First segment.
          ssize_t _M_first_segment = -1;

          // Last segment.
          ssize_t _M_last_segment = -1;

          // First free segment.
          ssize_t _M_free_segment = 0;

          // Payloads.
          uint8_t* _M_payloads = nullptr;

          // Next sequence number.
          uint32_t _M_next_seqno;

          // Payload callback.
          payloadfn_t _M_payloadfn;

          // Gap callback.
          gapfn_t _M_gapfn;

          // User pointer.
          void* _M_user;

          // Check payloads.
          void check_payloads();

          // Disable copy constructor and assignment operator.
          segments(const segments&) = delete;
          segments& operator=(const segments&) = delete;
      };

      inline segments::~segments()
      {
        if (_M_payloads) {
          free(_M_payloads);
        }
      }

      inline void segments::clear()
      {
        for (size_t i = 0; i < max_segments - 1; i++) {
          _M_segments[i].next = i + 1;
        }

        _M_segments[max_segments - 1].next = -1;

        _M_first_segment = -1;
        _M_last_segment = -1;
        _M_free_segment = 0;
      }

      inline void segments::next_sequence_number(uint32_t seqno)
      {
        _M_next_seqno = seqno;
      }
    }
  }
}

#endif // NET_MON_TCP_SEGMENTS_H
