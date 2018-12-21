#ifndef NET_MON_TCP_CONNECTION_H
#define NET_MON_TCP_CONNECTION_H

#include <stdint.h>
#include <sys/types.h>
#include "util/node.h"

namespace net {
  namespace mon {
    namespace tcp {
      class connection : private util::node {
        template<typename Connection>
        friend class connections;

        public:
          static constexpr const uint8_t ack = 0x10;
          static constexpr const uint8_t rst = 0x04;
          static constexpr const uint8_t syn = 0x02;
          static constexpr const uint8_t fin = 0x01;

          static constexpr const uint8_t flag_mask = ack | rst | syn | fin;

          // Connection state:
          // http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf
          enum class state : uint8_t {
            listen,
            connection_requested,
            connection_established,
            data_transfer,
            closing,
            closed,
            failure
          };

          // Originator.
          enum class originator : uint8_t {
            addr1,
            addr2
          };

          // Packet direction.
          enum class direction : uint8_t {
            from_addr1 = static_cast<uint8_t>(originator::addr1),
            from_addr2 = static_cast<uint8_t>(originator::addr2)
          };

          state s;

          originator active_opener;
          originator active_closer;

          uint64_t sent[2];

          struct {
            uint64_t creation;
            uint64_t last_packet;
          } timestamp;

          // Initialize.
          void init(direction dir, uint16_t size, uint64_t now);

          // Process packet.
          bool process_packet(direction dir,
                              uint8_t flags,
                              uint16_t size,
                              uint64_t now);
      };

      inline void connection::init(direction dir, uint16_t size, uint64_t now)
      {
        s = state::connection_requested;

        active_opener = static_cast<originator>(dir);

        sent[static_cast<size_t>(dir)] = size;
        sent[!static_cast<size_t>(dir)] = 0;

        timestamp.creation = now;
        timestamp.last_packet = now;
      }
    }
  }
}

#endif // NET_MON_TCP_CONNECTION_H
