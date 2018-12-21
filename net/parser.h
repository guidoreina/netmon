#ifndef NET_PARSER_H
#define NET_PARSER_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

namespace net {
  class parser {
    public:
      // Parser callbacks.
      struct callbacks {
        // Process ICMP datagram.
        typedef bool (*icmp_t)(const struct iphdr* iphdr,
                               size_t iphdrsize,
                               size_t pktsize,
                               const struct timeval& timestamp,
                               void* user);

        // Process ICMPv6 datagram.
        typedef bool (*icmpv6_t)(const struct ip6_hdr* iphdr,
                                 size_t iphdrsize,
                                 size_t pktsize,
                                 const struct timeval& timestamp,
                                 void* user);

        // Process TCP/IPv4 segment.
        typedef bool (*tcp_ipv4_t)(const struct iphdr* iphdr,
                                   size_t iphdrsize,
                                   size_t pktsize,
                                   const struct timeval& timestamp,
                                   void* user);

        // Process TCP/IPv6 segment.
        typedef bool (*tcp_ipv6_t)(const struct ip6_hdr* iphdr,
                                   size_t iphdrsize,
                                   size_t pktsize,
                                   const struct timeval& timestamp,
                                   void* user);

        // Process UDP/IPv4 segment.
        typedef bool (*udp_ipv4_t)(const struct iphdr* iphdr,
                                   size_t iphdrsize,
                                   size_t pktsize,
                                   const struct timeval& timestamp,
                                   void* user);

        // Process UDP/IPv6 segment.
        typedef bool (*udp_ipv6_t)(const struct ip6_hdr* iphdr,
                                   size_t iphdrsize,
                                   size_t pktsize,
                                   const struct timeval& timestamp,
                                   void* user);

        // Constructor.
        callbacks() = default;
        callbacks(icmp_t icmp,
                  icmpv6_t icmpv6,
                  tcp_ipv4_t tcp_ipv4,
                  tcp_ipv6_t tcp_ipv6,
                  udp_ipv4_t udp_ipv4,
                  udp_ipv6_t udp_ipv6);

        // Destructor.
        ~callbacks() = default;

        icmp_t icmp = nullptr;
        icmpv6_t icmpv6 = nullptr;
        tcp_ipv4_t tcp_ipv4 = nullptr;
        tcp_ipv6_t tcp_ipv6 = nullptr;
        udp_ipv4_t udp_ipv4 = nullptr;
        udp_ipv6_t udp_ipv6 = nullptr;
      };

      // Constructor.
      parser(const callbacks& callbacks, void* user = nullptr);

      // Destructor.
      ~parser() = default;

      // Process ethernet frame.
      bool process_ethernet(const void* buf,
                            size_t len,
                            const struct timeval& timestamp);

      // Process IPv4 packet.
      bool process_ipv4(const void* buf,
                        size_t len,
                        const struct timeval& timestamp);

      // Process IPv6 packet.
      bool process_ipv6(const void* buf,
                        size_t len,
                        const struct timeval& timestamp);

    private:
      callbacks _M_callbacks;

      void* _M_user;

      // Is extension header?
      static bool is_extension_header(uint8_t nxt);
  };

  inline parser::callbacks::callbacks(icmp_t icmp,
                                      icmpv6_t icmpv6,
                                      tcp_ipv4_t tcp_ipv4,
                                      tcp_ipv6_t tcp_ipv6,
                                      udp_ipv4_t udp_ipv4,
                                      udp_ipv6_t udp_ipv6)
    : icmp(icmp),
      icmpv6(icmpv6),
      tcp_ipv4(tcp_ipv4),
      tcp_ipv6(tcp_ipv6),
      udp_ipv4(udp_ipv4),
      udp_ipv6(udp_ipv6)
  {
  }

  inline parser::parser(const callbacks& callbacks, void* user)
    : _M_callbacks(callbacks),
      _M_user(user)
  {
  }

  inline bool parser::is_extension_header(uint8_t nxt)
  {
    switch (nxt) {
      case IPPROTO_HOPOPTS:  //   0: IPv6 hop-by-hop options.
      case IPPROTO_DSTOPTS:  //  60: IPv6 destination options.
      case IPPROTO_ROUTING:  //  43: IPv6 routing header.
      case IPPROTO_FRAGMENT: //  44: IPv6 fragmentation header.
      case 51:               //  51: Authentication header.
      case 50:               //  50: Encapsulating Security Payload.
      case IPPROTO_NONE:     //  59: IPv6 no next header.
      case IPPROTO_MH:       // 135: IPv6 mobility header.
      case 139:              // 139: Host Identity Protocol.
      case 140:              // 140: Shim6 Protocol.
        return true;
      default:
        return false;
    }
  }
}

#endif // NET_PARSER_H
