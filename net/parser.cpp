#include <net/ethernet.h>
#include <arpa/inet.h>
#include "net/parser.h"

bool net::parser::process_ethernet(const void* buf,
                                   size_t len,
                                   const struct timeval& timestamp)
{
  // If the frame is big enough...
  if (len > sizeof(struct ether_header)) {
    // Make 'b' point to the ether_type.
    const uint8_t* b = static_cast<const uint8_t*>(buf) +
                       (sizeof(struct ether_addr) << 1);

    // Subtract length of the ethernet header.
    len -= sizeof(struct ether_header);

    do {
      // Check ether_type.
      switch ((static_cast<uint16_t>(*b) << 8) | b[1]) {
        case ETH_P_IP:
          return process_ipv4(b + 2, len, timestamp);
        case ETH_P_IPV6:
          return process_ipv6(b + 2, len, timestamp);
        case ETH_P_8021Q:
        case ETH_P_8021AD:
          // If the frame is big enough...
          if (len > 4) {
            // Make 'b' point to the ether_type.
            b += 4;

            len -= 4;
          } else {
            return false;
          }

          break;
        case ETH_P_MPLS_UC:
        case ETH_P_MPLS_MC:
          // Skip ether_type.
          b += 2;

          do {
            // If the frame is big enough...
            if (len > 4) {
              // Bottom of the stack?
              if (b[2] & 0x01) {
                switch (((static_cast<uint32_t>(*b) << 12) |
                         (static_cast<uint32_t>(b[1]) << 8) |
                         (static_cast<uint32_t>(b[2]) >> 4)) & 0x0fffff) {
                  case 0: // IPv4.
                    return process_ipv4(b + 4, len - 4, timestamp);
                  case 2: // IPv6.
                    return process_ipv6(b + 4, len - 4, timestamp);
                  default:
                    // Check IP version.
                    switch (b[4] & 0xf0) {
                      case 0x40: // IPv4.
                        return process_ipv4(b + 4, len - 4, timestamp);
                      case 0x60: // IPv6.
                        return process_ipv6(b + 4, len - 4, timestamp);
                      default:
                        // Ignore frame.
                        return true;
                    }
                }
              } else {
                // Skip MPLS label.
                b += 4;

                len -= 4;
              }
            } else {
              return false;
            }
          } while (true);

          break;
        default:
          // Ignore frame.
          return true;
      }
    } while (true);
  }

  return false;
}

bool net::parser::process_ipv4(const void* buf,
                               size_t len,
                               const struct timeval& timestamp)
{
  // If the packet is big enough...
  if (len > sizeof(struct iphdr)) {
    const struct iphdr* iphdr = static_cast<const struct iphdr*>(buf);

    // Sanity check.
    if ((iphdr->ihl >= 5) &&
        (len > (static_cast<size_t>(iphdr->ihl) << 2)) &&
        (len == ntohs(iphdr->tot_len))) {
      switch (iphdr->protocol) {
        case IPPROTO_ICMP:
          return _M_callbacks.icmp ? 
                   _M_callbacks.icmp(iphdr,
                                     iphdr->ihl << 2,
                                     len,
                                     timestamp,
                                     _M_user) :
                   true;
        case IPPROTO_TCP:
          return _M_callbacks.tcp_ipv4 ? 
                   _M_callbacks.tcp_ipv4(iphdr,
                                         iphdr->ihl << 2,
                                         len,
                                         timestamp,
                                         _M_user) :
                   true;
        case IPPROTO_UDP:
          return _M_callbacks.udp_ipv4 ?
                   _M_callbacks.udp_ipv4(iphdr,
                                         iphdr->ihl << 2,
                                         len,
                                         timestamp,
                                         _M_user) :
                   true;
        default:
          // Ignore packet.
          return true;
      }
    }
  }

  return false;
}

bool net::parser::process_ipv6(const void* buf,
                               size_t len,
                               const struct timeval& timestamp)
{
  // If the packet is big enough...
  if (len > sizeof(struct ip6_hdr)) {
    const struct ip6_hdr* iphdr = static_cast<const struct ip6_hdr*>(buf);

    // Get payload length (including extension headers).
    uint16_t payload_length = ntohs(iphdr->ip6_plen);

    // Sanity check.
    if (sizeof(struct ip6_hdr) + payload_length == len) {
      uint8_t nxt;
      switch (nxt = iphdr->ip6_nxt) {
        case IPPROTO_ICMPV6:
          return _M_callbacks.icmpv6 ?
                   _M_callbacks.icmpv6(iphdr,
                                       sizeof(struct ip6_hdr),
                                       len,
                                       timestamp,
                                       _M_user) :
                   true;
        case IPPROTO_TCP:
          return _M_callbacks.tcp_ipv6 ?
                   _M_callbacks.tcp_ipv6(iphdr,
                                         sizeof(struct ip6_hdr),
                                         len,
                                         timestamp,
                                         _M_user) :
                   true;
        case IPPROTO_UDP:
          return _M_callbacks.udp_ipv6 ?
                   _M_callbacks.udp_ipv6(iphdr,
                                         sizeof(struct ip6_hdr),
                                         len,
                                         timestamp,
                                         _M_user) :
                   true;
        default:
          {
            size_t off = sizeof(struct ip6_hdr);

            while (is_extension_header(nxt)) {
              if (payload_length >= sizeof(struct ip6_ext)) {
                const struct ip6_ext* ext =
                      reinterpret_cast<const struct ip6_ext*>(
                        static_cast<const uint8_t*>(buf) + off
                      );

                // Compute length of the extension header.
                size_t extlen = (ext->ip6e_len + 1) << 3;

                if (extlen <= payload_length) {
                  off += extlen;

                  switch (nxt = ext->ip6e_nxt) {
                    case IPPROTO_ICMPV6:
                      return _M_callbacks.icmpv6 ?
                               _M_callbacks.icmpv6(iphdr,
                                                   off,
                                                   len,
                                                   timestamp,
                                                   _M_user) :
                               true;
                    case IPPROTO_TCP:
                      return _M_callbacks.tcp_ipv6 ?
                               _M_callbacks.tcp_ipv6(iphdr,
                                                     off,
                                                     len,
                                                     timestamp,
                                                     _M_user) :
                               true;
                    case IPPROTO_UDP:
                      return _M_callbacks.udp_ipv6 ?
                               _M_callbacks.udp_ipv6(iphdr,
                                                     off,
                                                     len,
                                                     timestamp,
                                                     _M_user) :
                               true;
                    default:
                      payload_length -= extlen;
                  }
                } else {
                  return false;
                }
              } else {
                return false;
              }
            }

            // Ignore packet.
            return true;
          }
      }
    }
  }

  return false;
}
