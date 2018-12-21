#ifndef PCAP_H
#define PCAP_H

#include <stdint.h>

namespace pcap {
  enum class magic : uint32_t {
    microseconds = 0xa1b2c3d4,
    nanoseconds = 0xa1b23c4d
  };

  static constexpr const uint16_t version_major = 2;
  static constexpr const uint16_t version_minor = 4;

  enum class linklayer_header : uint32_t {
    ethernet = 1,
    raw = 101,
    linux_sll = 113
  };

  struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
  };

  struct timeval {
    uint32_t tv_sec;
    uint32_t tv_usec;
  };

  struct pcap_pkthdr {
    timeval ts;
    uint32_t caplen;
    uint32_t len;
  };

  enum class resolution {
    microseconds,
    nanoseconds
  };
}

#endif // PCAP_H
