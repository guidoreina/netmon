#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include "pcap/reader.h"

bool pcap::reader::open(const char* filename)
{
  // If the file exists and is big enough to contain the PCAP file header...
  struct stat sbuf;
  if ((stat(filename, &sbuf) == 0) &&
      (S_ISREG(sbuf.st_mode)) &&
      (sbuf.st_size >= static_cast<off_t>(sizeof(pcap_file_header)))) {
    // Open file for reading.
    if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
      // Map file into memory.
      if ((_M_base = mmap(nullptr,
                          sbuf.st_size,
                          PROT_READ,
                          MAP_SHARED,
                          _M_fd,
                          0)) != MAP_FAILED) {
        // Save file size.
        _M_filesize = sbuf.st_size;

        // Check magic.
        switch (static_cast<magic>(file_header()->magic)) {
          case magic::microseconds:
            _M_resolution = pcap::resolution::microseconds;
            break;
          case magic::nanoseconds:
            _M_resolution = pcap::resolution::nanoseconds;
            break;
          default:
            return false;
        }

        // Version 2.4?
        if ((file_header()->version_major == version_major) &&
            (file_header()->version_minor == version_minor)) {
          // Make '_M_end' point to the end.
          _M_end = static_cast<const uint8_t*>(_M_base) + _M_filesize;

          // Make '_M_ptr' point to the first packet.
          _M_ptr = static_cast<const uint8_t*>(_M_base) +
                   sizeof(pcap_file_header);

          return true;
        }
      }
    }
  }

  return false;
}

void pcap::reader::close()
{
  if (_M_base != MAP_FAILED) {
    munmap(_M_base, _M_filesize);
    _M_base = MAP_FAILED;
  }

  if (_M_fd != -1) {
    ::close(_M_fd);
    _M_fd = -1;
  }
}

const void* pcap::reader::next(pcap_pkthdr& hdr)
{
  if (_M_ptr + sizeof(pcap_pkthdr) <= _M_end) {
    const pcap_pkthdr* h = reinterpret_cast<const pcap_pkthdr*>(_M_ptr);

    const uint8_t* next;
    if ((next = _M_ptr + sizeof(pcap_pkthdr) + h->caplen) <= _M_end) {
      _M_ptr = next;

      hdr = *h;

      return reinterpret_cast<const uint8_t*>(h) + sizeof(pcap_pkthdr);
    }
  }

  return nullptr;
}

bool pcap::reader::read_ethernet(const callbacks& callbacks, void* user)
{
  if ((callbacks.ipv4) && (callbacks.ipv6)) {
    pcap_pkthdr pkthdr;
    const void* pkt;

    while ((pkt = next(pkthdr)) != nullptr) {
      // Process ethernet frame.
      if (!process_ethernet(pkthdr, pkt, callbacks, user)) {
        return false;
      }
    }
  } else if (callbacks.ethernet) {
    pcap_pkthdr pkthdr;
    const void* pkt;

    while ((pkt = next(pkthdr)) != nullptr) {
      if (!callbacks.ethernet(pkt, pkthdr.caplen, pkthdr.ts, user)) {
        return false;
      }
    }
  } else {
    return false;
  }

  return true;
}

bool pcap::reader::read_raw(const callbacks& callbacks, void* user)
{
  if ((callbacks.ipv4) && (callbacks.ipv6)) {
    pcap_pkthdr pkthdr;
    const void* pkt;

    while ((pkt = next(pkthdr)) != nullptr) {
      // If the frame is big enough...
      if (pkthdr.caplen > sizeof(struct iphdr)) {
        // Check IP version.
        switch (*static_cast<const uint8_t*>(pkt) & 0xf0) {
          case 0x40: // IPv4.
            if (!callbacks.ipv4(pkt, pkthdr.caplen, pkthdr.ts, user)) {
              return false;
            }

            break;
          case 0x60: // IPv6.
            if (!callbacks.ipv6(pkt, pkthdr.caplen, pkthdr.ts, user)) {
              return false;
            }

            break;
        }
      }
    }

    return true;
  } else {
    return false;
  }
}

bool pcap::reader::read_linux_sll(const callbacks& callbacks, void* user)
{
  if ((callbacks.ipv4) && (callbacks.ipv6)) {
    pcap_pkthdr pkthdr;
    const void* pkt;

    while ((pkt = next(pkthdr)) != nullptr) {
      // If the frame is big enough...
      if (pkthdr.caplen > 16) {
        const uint8_t* b = static_cast<const uint8_t*>(pkt);

        if ((((static_cast<uint16_t>(b[2]) << 8) | b[3]) == ARPHRD_ETHER) &&
            (((static_cast<uint16_t>(b[4]) << 8) | b[5]) == ETH_ALEN)) {
          // The Linux SLL header is two bytes longer than the ethernet header.
          pkthdr.caplen -= 2;
          pkthdr.len -= 2;

          if (!process_ethernet(pkthdr, b + 2, callbacks, user)) {
            return false;
          }
        }
      }
    }

    return true;
  } else {
    return false;
  }
}

bool pcap::reader::process_ethernet(const pcap_pkthdr& pkthdr,
                                    const void* pkt,
                                    const callbacks& callbacks,
                                    void* user)
{
  // If the frame is big enough...
  if (pkthdr.caplen > sizeof(struct ether_header)) {
    // Make 'b' point to the ether_type.
    const uint8_t* b = static_cast<const uint8_t*>(pkt) +
                       (sizeof(struct ether_addr) << 1);

    // Subtract length of the ethernet header.
    size_t len = pkthdr.caplen - sizeof(struct ether_header);

    do {
      // Check ether_type.
      switch ((static_cast<uint16_t>(*b) << 8) | b[1]) {
        case ETH_P_IP:
          return callbacks.ipv4(b + 2, len, pkthdr.ts, user);
        case ETH_P_IPV6:
          return callbacks.ipv6(b + 2, len, pkthdr.ts, user);
        case ETH_P_8021Q:
        case ETH_P_8021AD:
          // If the frame is big enough...
          if (len > 4) {
            // Make 'b' point to the ether_type.
            b += 4;

            len -= 4;
          } else {
            // Ignore frame.
            return true;
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
                    return callbacks.ipv4(b + 4, len - 4, pkthdr.ts, user);
                  case 2: // IPv6.
                    return callbacks.ipv6(b + 4, len - 4, pkthdr.ts, user);
                  default:
                    // Check IP version.
                    switch (b[4] & 0xf0) {
                      case 0x40: // IPv4.
                        return callbacks.ipv4(b + 4, len - 4, pkthdr.ts, user);
                      case 0x60: // IPv6.
                        return callbacks.ipv6(b + 4, len - 4, pkthdr.ts, user);
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
              // Ignore frame.
              return true;
            }
          } while (true);

          break;
        default:
          // Ignore frame.
          return true;
      }
    } while (true);
  }

  // Ignore frame.
  return true;
}
