#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include "net/mon/worker.h"
#include "net/mon/dns/message.h"

static inline uint8_t tcp_flags(const struct tcphdr* tcphdr)
{
  return reinterpret_cast<const uint8_t*>(tcphdr)[13];
}

bool net::mon::worker::start()
{
  if (_M_nprocessor == no_processor) {
    // Start thread.
    return (_M_running = (pthread_create(&_M_thread,
                                         nullptr,
                                         run,
                                         this) == 0));
  } else {
    // Initialize thread attributes.
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
      cpu_set_t cpuset;
      CPU_ZERO(&cpuset);
      CPU_SET(_M_nprocessor, &cpuset);

      // Set the CPU affinity of the thread.
      if (pthread_attr_setaffinity_np(&attr,
                                      sizeof(cpu_set_t),
                                      &cpuset) == 0) {
        // Start thread.
        if (pthread_create(&_M_thread, &attr, run, this) == 0) {
          _M_running = true;

          pthread_attr_destroy(&attr);

          return true;
        }
      }

      pthread_attr_destroy(&attr);
    }

    return false;
  }
}

bool net::mon::worker::icmp(const struct iphdr* iphdr,
                            size_t iphdrsize,
                            size_t pktsize,
                            const struct timeval& timestamp,
                            void* user)
{
  // If the ICMP datagram is big enough...
  if (pktsize - iphdrsize >= sizeof(struct icmphdr)) {
    const struct icmphdr* icmphdr = reinterpret_cast<const struct icmphdr*>(
                                      reinterpret_cast<const uint8_t*>(iphdr) +
                                      iphdrsize
                                    );

    event::icmp ev;

    ev.addrlen = static_cast<uint8_t>(sizeof(struct in_addr));

    memcpy(ev.saddr, &iphdr->saddr, sizeof(struct in_addr));
    memcpy(ev.daddr, &iphdr->daddr, sizeof(struct in_addr));

    ev.timestamp = to_microseconds(timestamp);

    ev.icmp_type = icmphdr->type;
    ev.icmp_code = icmphdr->code;

    ev.transferred = pktsize;

    static_cast<worker*>(user)->_M_evwriter.write(ev);

    return true;
  }

  return true;
}

bool net::mon::worker::icmpv6(const struct ip6_hdr* iphdr,
                              size_t iphdrsize,
                              size_t pktsize,
                              const struct timeval& timestamp,
                              void* user)
{
  // If the ICMPv6 datagram is big enough...
  if (pktsize - iphdrsize >= sizeof(struct icmp6_hdr)) {
    const struct icmp6_hdr* icmphdr =
          reinterpret_cast<const struct icmp6_hdr*>(
            reinterpret_cast<const uint8_t*>(iphdr) +
            iphdrsize
          );

    event::icmp ev;

    ev.addrlen = static_cast<uint8_t>(sizeof(struct in6_addr));

    memcpy(ev.saddr, &iphdr->ip6_src, sizeof(struct in6_addr));
    memcpy(ev.daddr, &iphdr->ip6_dst, sizeof(struct in6_addr));

    ev.timestamp = to_microseconds(timestamp);

    ev.icmp_type = icmphdr->icmp6_type;
    ev.icmp_code = icmphdr->icmp6_code;

    ev.transferred = pktsize;

    static_cast<worker*>(user)->_M_evwriter.write(ev);

    return true;
  }

  return true;
}

bool net::mon::worker::tcp_ipv4(const struct iphdr* iphdr,
                                size_t iphdrsize,
                                size_t pktsize,
                                const struct timeval& timestamp,
                                void* user)
{
  // If the TCP segment is big enough...
  size_t tcpsize;
  if ((tcpsize = pktsize - iphdrsize) >= sizeof(struct tcphdr)) {
    const struct tcphdr* tcphdr = reinterpret_cast<const struct tcphdr*>(
                                    reinterpret_cast<const uint8_t*>(iphdr) +
                                    iphdrsize
                                  );

    // Sanity check.
    if ((tcphdr->doff >= 5) &&
        (tcpsize >= (static_cast<size_t>(tcphdr->doff) << 2))) {
      return static_cast<worker*>(user)->_M_tcp_ipv4.add(
               static_cast<const ipv4::address&>(iphdr->saddr),
               tcphdr->source,
               static_cast<const ipv4::address&>(iphdr->daddr),
               tcphdr->dest,
               tcp_flags(tcphdr),
               pktsize,
               tcpsize - (tcphdr->doff << 2),
               to_microseconds(timestamp)
             );
    }
  }

  return true;
}

bool net::mon::worker::tcp_ipv6(const struct ip6_hdr* iphdr,
                                size_t iphdrsize,
                                size_t pktsize,
                                const struct timeval& timestamp,
                                void* user)
{
  // If the TCP segment is big enough...
  size_t tcpsize;
  if ((tcpsize = pktsize - iphdrsize) >= sizeof(struct tcphdr)) {
    const struct tcphdr* tcphdr = reinterpret_cast<const struct tcphdr*>(
                                    reinterpret_cast<const uint8_t*>(iphdr) +
                                    iphdrsize
                                  );

    // Sanity check.
    if ((tcphdr->doff >= 5) &&
        (tcpsize >= (static_cast<size_t>(tcphdr->doff) << 2))) {
      return static_cast<worker*>(user)->_M_tcp_ipv6.add(
               static_cast<const ipv6::address&>(iphdr->ip6_src),
               tcphdr->source,
               static_cast<const ipv6::address&>(iphdr->ip6_dst),
               tcphdr->dest,
               tcp_flags(tcphdr),
               pktsize,
               tcpsize - (tcphdr->doff << 2),
               to_microseconds(timestamp)
             );
    }
  }

  return true;
}

bool net::mon::worker::udp_ipv4(const struct iphdr* iphdr,
                                size_t iphdrsize,
                                size_t pktsize,
                                const struct timeval& timestamp,
                                void* user)
{
  // If the UDP datagram is big enough...
  if (pktsize - iphdrsize >= sizeof(struct udphdr)) {
    const struct udphdr* udphdr = reinterpret_cast<const struct udphdr*>(
                                    reinterpret_cast<const uint8_t*>(iphdr) +
                                    iphdrsize
                                  );

    // Sanity check.
    uint16_t udplen = ntohs(udphdr->len);
    if ((udplen >= sizeof(struct udphdr)) && (iphdrsize + udplen == pktsize)) {
      // DNS request or response?
      if ((udphdr->source == dns::port) || (udphdr->dest == dns::port)) {
        // Process 'DNS'.
        dns::message dnsmsg(reinterpret_cast<const uint8_t*>(udphdr) +
                            sizeof(struct udphdr),
                            udplen - sizeof(struct udphdr));

        event::dns ev;

        // Parse DNS message.
        if (dnsmsg.parse(ev)) {
          ev.addrlen = static_cast<uint8_t>(sizeof(struct in_addr));

          memcpy(ev.saddr, &iphdr->saddr, sizeof(struct in_addr));
          memcpy(ev.daddr, &iphdr->daddr, sizeof(struct in_addr));

          ev.sport = udphdr->source;
          ev.dport = udphdr->dest;

          ev.timestamp = to_microseconds(timestamp);

          ev.transferred = pktsize;

          static_cast<worker*>(user)->_M_evwriter.write(ev);

          return true;
        }
      }

      event::udp ev;

      ev.addrlen = static_cast<uint8_t>(sizeof(struct in_addr));

      memcpy(ev.saddr, &iphdr->saddr, sizeof(struct in_addr));
      memcpy(ev.daddr, &iphdr->daddr, sizeof(struct in_addr));

      ev.sport = udphdr->source;
      ev.dport = udphdr->dest;

      ev.timestamp = to_microseconds(timestamp);

      ev.transferred = pktsize;

      static_cast<worker*>(user)->_M_evwriter.write(ev);

      return true;
    }
  }

  return true;
}

bool net::mon::worker::udp_ipv6(const struct ip6_hdr* iphdr,
                                size_t iphdrsize,
                                size_t pktsize,
                                const struct timeval& timestamp,
                                void* user)
{
  // If the UDP datagram is big enough...
  if (pktsize - iphdrsize >= sizeof(struct udphdr)) {
    const struct udphdr* udphdr = reinterpret_cast<const struct udphdr*>(
                                    reinterpret_cast<const uint8_t*>(iphdr) +
                                    iphdrsize
                                  );

    // Sanity check.
    uint16_t udplen = ntohs(udphdr->len);
    if ((udplen >= sizeof(struct udphdr)) && (iphdrsize + udplen == pktsize)) {
      // DNS request or response?
      if ((udphdr->source == dns::port) || (udphdr->dest == dns::port)) {
        // Process 'DNS'.
        dns::message dnsmsg(reinterpret_cast<const uint8_t*>(udphdr) +
                            sizeof(struct udphdr),
                            udplen - sizeof(struct udphdr));

        event::dns ev;

        // Parse DNS message.
        if (dnsmsg.parse(ev)) {
          ev.addrlen = static_cast<uint8_t>(sizeof(struct in6_addr));

          memcpy(ev.saddr, &iphdr->ip6_src, sizeof(struct in6_addr));
          memcpy(ev.daddr, &iphdr->ip6_dst, sizeof(struct in6_addr));

          ev.sport = udphdr->source;
          ev.dport = udphdr->dest;

          ev.timestamp = to_microseconds(timestamp);

          ev.transferred = pktsize;

          static_cast<worker*>(user)->_M_evwriter.write(ev);

          return true;
        }
      }

      event::udp ev;

      ev.addrlen = static_cast<uint8_t>(sizeof(struct in6_addr));

      memcpy(ev.saddr, &iphdr->ip6_src, sizeof(struct in6_addr));
      memcpy(ev.daddr, &iphdr->ip6_dst, sizeof(struct in6_addr));

      ev.sport = udphdr->source;
      ev.dport = udphdr->dest;

      ev.timestamp = to_microseconds(timestamp);

      ev.transferred = pktsize;

      static_cast<worker*>(user)->_M_evwriter.write(ev);

      return true;
    }
  }

  return true;
}
