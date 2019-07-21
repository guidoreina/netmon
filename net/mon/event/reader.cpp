#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "net/mon/event/reader.h"

bool net::mon::event::reader::open(const char* filename)
{
  // If the file exists and is a regular file...
  struct stat sbuf;
  if ((stat(filename, &sbuf) == 0) && (S_ISREG(sbuf.st_mode))) {
    // Open file for reading.
    if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
      // Map file into memory.
      if ((_M_base = mmap(nullptr,
                          sbuf.st_size,
                          PROT_READ,
                          MAP_SHARED,
                          _M_fd,
                          0)) != MAP_FAILED) {
        // Deserialize header.
        if (_M_header.deserialize(_M_base, sbuf.st_size)) {
          // Initialize DNS caches.
          using namespace net::mon::dns;
          if ((_M_ipv4_dns_cache.init(inverted_cache<ipv4::address>::
                                      default_size)) &&
              (_M_ipv6_dns_cache.init(inverted_cache<ipv6::address>::
                                      default_size))) {
            // Save file size.
            _M_filesize = sbuf.st_size;

            // Make '_M_end' point to the end.
            _M_end = static_cast<const uint8_t*>(_M_base) + _M_filesize;

            // Make '_M_ptr' point to the first event.
            _M_ptr = static_cast<const uint8_t*>(_M_base) + file::header::size;

            return true;
          }
        }
      }
    }
  }

  return false;
}

bool net::mon::event::reader::next(const grammar::conditional_expression* expr)
{
  if (_M_printer) {
    size_t left;
    while ((left = _M_end - _M_ptr) >= minlen) {
      // Extract event length.
      evlen_t len = base::extract_length(_M_ptr);

      // If the event fits and is not too small...
      if ((len <= left) && (len >= minlen)) {
        // Check event type.
        switch (base::extract_type(_M_ptr)) {
          case type::icmp:
            {
              // Build 'ICMP' event.
              icmp ev;
              if (ev.build(_M_ptr, len)) {
                const char* srchostname = source_host(ev);
                const char* desthostname = destination_host(ev);

                if ((!expr) ||
                    (expr->evaluate(ev, srchostname, desthostname))) {
                  _M_printer->print(++_M_nevent, ev, srchostname, desthostname);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
          case type::udp:
            {
              // Build 'UDP' event.
              udp ev;
              if (ev.build(_M_ptr, len)) {
                const char* srchostname = source_host(ev);
                const char* desthostname = destination_host(ev);

                if ((!expr) ||
                    (expr->evaluate(ev, srchostname, desthostname))) {
                  _M_printer->print(++_M_nevent, ev, srchostname, desthostname);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
          case type::dns:
            {
              // Build 'DNS' event.
              dns ev;
              if (ev.build(_M_ptr, len)) {
                // If it is a response...
                if (ev.nresponses > 0) {
                  // For each response...
                  for (size_t i = 0; i < ev.nresponses; i++) {
                    // IPv4?
                    if (ev.responses[i].addrlen == 4) {
                      ipv4::address addr(ev.responses[i].addr);

                      // Add pair (address, host) to the IPv4 DNS inverted
                      // cache.
                      if (!_M_ipv4_dns_cache.add(addr,
                                                 ev.domain,
                                                 ev.domainlen)) {
                        return false;
                      }
                    } else {
                      ipv6::address addr(ev.responses[i].addr);

                      // Add pair (address, host) to the IPv6 DNS inverted
                      // cache.
                      if (!_M_ipv6_dns_cache.add(addr,
                                                 ev.domain,
                                                 ev.domainlen)) {
                        return false;
                      }
                    }
                  }
                }

                if ((!expr) || (expr->evaluate(ev, nullptr, nullptr))) {
                  _M_printer->print(++_M_nevent, ev, nullptr, nullptr);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
          case type::tcp_begin:
            {
              // Build 'Begin TCP connection' event.
              tcp_begin ev;
              if (ev.build(_M_ptr, len)) {
                const char* srchostname = source_host(ev);
                const char* desthostname = destination_host(ev);

                if ((!expr) ||
                    (expr->evaluate(ev, srchostname, desthostname))) {
                  _M_printer->print(++_M_nevent, ev, srchostname, desthostname);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
          case type::tcp_data:
            {
              // Build 'TCP data' event.
              tcp_data ev;
              if (ev.build(_M_ptr, len)) {
                const char* srchostname = source_host(ev);
                const char* desthostname = destination_host(ev);

                if ((!expr) ||
                    (expr->evaluate(ev, srchostname, desthostname))) {
                  _M_printer->print(++_M_nevent, ev, srchostname, desthostname);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
          case type::tcp_end:
            {
              // Build 'End TCP connection' event.
              tcp_end ev;
              if (ev.build(_M_ptr, len)) {
                const char* srchostname = source_host(ev);
                const char* desthostname = destination_host(ev);

                if ((!expr) ||
                    (expr->evaluate(ev, srchostname, desthostname))) {
                  _M_printer->print(++_M_nevent, ev, srchostname, desthostname);
                }

                _M_ptr += len;

                return true;
              } else {
                return false;
              }
            }

            break;
        }
      } else {
        return false;
      }
    }
  }

  return false;
}

bool net::mon::event::reader::next(const void*& event,
                                   size_t& len,
                                   uint64_t& timestamp)
{
  size_t left;
  if ((left = _M_end - _M_ptr) >= minlen) {
    // Extract event length.
    evlen_t l = base::extract_length(_M_ptr);

    // If the event fits and is not too small...
    if ((l <= left) && (l >= minlen)) {
      event = _M_ptr;
      len = l;

      // Extract timestamp.
      timestamp = base::extract_timestamp(_M_ptr);

      _M_ptr += l;

      return true;
    }
  }

  return false;
}
