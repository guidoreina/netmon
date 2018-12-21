#include <string.h>
#include "net/mon/dns/message.h"

bool net::mon::dns::message::parse(event::dns& ev)
{
  // If the DNS message should be processed...
  if ((_M_len >= header_len)           && // The message is not too short.
      (_M_len <= max_len)              && // The message is not too long.
      (((_M_buf[2] >> 3) & 0x0f) <= 2) && // 0 <= OPCODE <= 2
      ((_M_buf[2] & 0x02) == 0)        && // The message was not truncated.
      ((_M_buf[3] & 0x0f) == 0)) {        // RCODE = 0
    uint16_t qdcount = (static_cast<uint16_t>(_M_buf[4]) << 8) | _M_buf[5];

    // If there are questions...
    if (qdcount > 0) {
      _M_off = header_len;

      // If the QNAME is valid and the QTYPE and QCLASS fit...
      if ((parse_domain_name(ev.domain, ev.domainlen)) &&
          (_M_off + 4 <= _M_len)) {
        // If the QCLASS is 1 (IN [Internet])...
        if (((static_cast<uint16_t>(_M_buf[_M_off + 2]) << 8) |
             _M_buf[_M_off + 3]) == 1) {
          // Get QTYPE.
          uint16_t qtype = (static_cast<uint16_t>(_M_buf[_M_off]) << 8) |
                           _M_buf[_M_off + 1];

          if (qtype <= 255) {
            ev.qtype = static_cast<uint8_t>(qtype);

            ev.nresponses = 0;

            // Query?
            if ((_M_buf[2] & 0x80) == 0) {
                return true;
            } else {
              uint16_t ancount = (static_cast<uint16_t>(_M_buf[6]) << 8) |
                                 _M_buf[7];

              // If there are answers...
              if (ancount > 0) {
                // Skip QTYPE and QCLASS.
                _M_off += 4;

                // Skip following questions (if any).
                for (size_t i = 2; i <= qdcount; i++) {
                  if (!skip_question()) {
                    return false;
                  }
                }

                // Process answers.
                for (size_t i = 1; i <= ancount; i++) {
                  if ((skip_domain_name()) && (_M_off + 10 <= _M_len)) {
                    uint16_t rdlength =
                             (static_cast<uint16_t>(_M_buf[_M_off + 8]) << 8) |
                             _M_buf[_M_off + 9];

                    size_t next;
                    if ((next = _M_off + 10 + rdlength) <= _M_len) {
                      // If the CLASS is 1 (IN [Internet])...
                      if (((static_cast<uint16_t>(_M_buf[_M_off + 2]) << 8) |
                           _M_buf[_M_off + 3]) == 1) {
                        // Check type.
                        switch ((static_cast<uint16_t>(_M_buf[_M_off]) << 8) |
                                _M_buf[_M_off + 1]) {
                          case 1: // A (host address [IPv4]).
                            if (rdlength == 4) {
                              ev.responses[ev.nresponses].addrlen = 4;

                              memcpy(ev.responses[ev.nresponses].addr,
                                     _M_buf + _M_off + 10,
                                     4);

                              if (++ev.nresponses ==
                                  event::dns::max_responses) {
                                return true;
                              }
                            } else {
                              return false;
                            }

                            break;
                          case 28: // AAAA (IPv6).
                            if (rdlength == 16) {
                              ev.responses[ev.nresponses].addrlen = 16;

                              memcpy(ev.responses[ev.nresponses].addr,
                                     _M_buf + _M_off + 10,
                                     16);

                              if (++ev.nresponses ==
                                  event::dns::max_responses) {
                                return true;
                              }
                            } else {
                              return false;
                            }

                            break;
                        }
                      }

                      _M_off = next;
                    } else {
                      return false;
                    }
                  } else {
                    return false;
                  }
                }

                return (ev.nresponses > 0);
              }
            }
          }
        }
      }
    }
  }

  return false;
}

bool net::mon::dns::message::parse_domain_name(char* domain, uint8_t& domainlen)
{
  size_t len = 0;
  size_t npointers = 0;

  // Work with a copy of the offset.
  size_t off = _M_off;

  while (off < _M_len) {
    switch (_M_buf[off] & 0xc0) {
      case 0: // Label.
        // If not the null label...
        if (_M_buf[off] > 0) {
          size_t next;
          if (((next = off + 1 + _M_buf[off]) < _M_len) &&
              (len + 1 + _M_buf[off] <= domain_name_max_len)) {
            // If not the first label...
            if (len > 0) {
              domain[len++] = '.';
            }

            // Copy label.
            memcpy(domain + len, _M_buf + off + 1, _M_buf[off]);

            len += _M_buf[off];

            off = next;
          } else {
            return false;
          }
        } else {
          // Null label.

          domainlen = static_cast<uint8_t>(len);

          if (npointers == 0) {
            _M_off = off + 1;
          }

          return true;
        }

        break;
      case 0xc0: // Pointer.
        if ((++npointers <= max_pointers) && (off + 1 < _M_len)) {
          // Compute pointer offset.
          size_t ptroff = (static_cast<uint16_t>(_M_buf[off] & 0x3f) << 8) |
                          _M_buf[off + 1];

          // Valid offset?
          if ((ptroff >= header_len) && (ptroff < _M_len)) {
            // First pointer?
            if (npointers == 1) {
              _M_off = off + 2;
            }

            off = ptroff;
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      default:
        return false;
    }
  }

  return false;
}

bool net::mon::dns::message::skip_domain_name()
{
  size_t len = 0;
  size_t npointers = 0;

  // Work with a copy of the offset.
  size_t off = _M_off;

  while (off < _M_len) {
    switch (_M_buf[off] & 0xc0) {
      case 0: // Label.
        // If not the null label...
        if (_M_buf[off] > 0) {
          size_t next;
          if (((next = off + 1 + _M_buf[off]) < _M_len) &&
              (len + 1 + _M_buf[off] <= domain_name_max_len)) {
            // If not the first label...
            if (len > 0) {
              len += (1 + _M_buf[off]);
            } else {
              len += _M_buf[off];
            }

            off = next;
          } else {
            return false;
          }
        } else {
          // Null label.

          if (npointers == 0) {
            _M_off = off + 1;
          }

          return true;
        }

        break;
      case 0xc0: // Pointer.
        if ((++npointers <= max_pointers) && (off + 1 < _M_len)) {
          // Compute pointer offset.
          size_t ptroff = (static_cast<uint16_t>(_M_buf[off] & 0x3f) << 8) |
                          _M_buf[off + 1];

          // Valid offset?
          if ((ptroff >= header_len) && (ptroff < _M_len)) {
            // First pointer?
            if (npointers == 1) {
              _M_off = off + 2;
            }

            off = ptroff;
          } else {
            return false;
          }
        } else {
          return false;
        }

        break;
      default:
        return false;
    }
  }

  return false;
}
