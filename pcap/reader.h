#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <sys/mman.h>
#include "pcap/pcap.h"

namespace pcap {
  // Packet callbacks.
  struct callbacks {
    bool (*ethernet)(const void* buf,
                     size_t len,
                     const struct timeval& timestamp,
                     void* user) = nullptr;

    bool (*ipv4)(const void* buf,
                 size_t len,
                 const struct timeval& timestamp,
                 void* user) = nullptr;

    bool (*ipv6)(const void* buf,
                 size_t len,
                 const struct timeval& timestamp,
                 void* user) = nullptr;
  };

  class reader {
    public:
      // Constructor.
      reader() = default;

      // Destructor.
      ~reader();

      // Open PCAP file.
      bool open(const char* filename);

      // Close PCAP file.
      void close();

      // Get next packet.
      const void* next(pcap_pkthdr& pkthdr);

      // Read all file.
      bool read_all(const callbacks& callbacks, void* user = nullptr);

      // Get PCAP file header.
      const pcap_file_header* file_header() const;

      // Get resolution.
      pcap::resolution resolution() const;

    private:
      int _M_fd = -1;

      void* _M_base = MAP_FAILED;

      // Size of the file.
      size_t _M_filesize;

      // Pointer to the end.
      const uint8_t* _M_end;

      // Pointer to the next packet.
      const uint8_t* _M_ptr;

      // Resolution.
      pcap::resolution _M_resolution;

      // Read ethernet file.
      bool read_ethernet(const callbacks& callbacks, void* user);

      // Read raw file.
      bool read_raw(const callbacks& callbacks, void* user);

      // Read Linux SLL file.
      bool read_linux_sll(const callbacks& callbacks, void* user);

      // Process ethernet frame.
      static bool process_ethernet(const pcap_pkthdr& pkthdr,
                                   const void* pkt,
                                   const callbacks& callbacks,
                                   void* user);

      // Disable copy constructor and assignment operator.
      reader(const reader&) = delete;
      reader& operator=(const reader&) = delete;
  };

  inline reader::~reader()
  {
    close();
  }

  inline bool reader::read_all(const callbacks& callbacks, void* user)
  {
    switch (static_cast<linklayer_header>(file_header()->linktype)) {
      case linklayer_header::ethernet:
        return read_ethernet(callbacks, user);
      case linklayer_header::raw:
        return read_raw(callbacks, user);
      case linklayer_header::linux_sll:
        return read_linux_sll(callbacks, user);
      default:
        return false;
    }
  }

  inline const pcap_file_header* reader::file_header() const
  {
    return static_cast<const pcap_file_header*>(_M_base);
  }

  inline pcap::resolution reader::resolution() const
  {
    return _M_resolution;
  }
}

#endif // PCAP_READER_H
