#include <stdio.h>
#include <arpa/inet.h>
#include "net/mon/event/dns.h"

bool net::mon::event::dns::build(const void* buf, size_t len)
{
  if (base::build(buf, len)) {
    // Set 'off' to the offset of the 'DNS' event.
    size_t off = base::size();

    if (len > off + 8) {
      // Make 'b' point after the base event.
      const uint8_t* b = static_cast<const uint8_t*>(buf) + off;

      // Extract domain length.
      domainlen = b[7];

      if ((domainlen > 0) && (len > off + 8 + domainlen)) {
        // Extract number of responses.
        nresponses = b[8 + domainlen];

        if (nresponses <= max_responses) {
          // Extract source port.
          deserialize(sport, b);

          // Extract destination port.
          deserialize(dport, b + 2);

          // Extract transferred.
          deserialize(transferred, b + 4);

          // Extract QTYPE.
          qtype = b[6];

          // Copy domain.
          memcpy(domain, b + 8, domainlen);

          // Make 'b' point to the first response.
          b += (8 + domainlen + 1);

          // Make 'end' point to the end of the event.
          const uint8_t* const end = static_cast<const uint8_t*>(buf) + len;

          // For each response...
          for (size_t i = 0; i < nresponses; i++) {
            if ((b < end) && (b + *b <= end)) {
              switch (*b) {
                case 4: // IPv4.
                case 16: // IPv6.
                  // Extract address length.
                  responses[i].addrlen = *b++;

                  // Copy address.
                  memcpy(responses[i].addr, b, responses[i].addrlen);

                  // Skip address.
                  b += responses[i].addrlen;

                  break;
                default:
                  return false;
              }
            } else {
              return false;
            }
          }

          return (b == end);
        }
      }
    }
  }

  return false;
}

bool net::mon::event::dns::serialize(string::buffer& buf) const
{
  // Allocate memory for the event.
  if (buf.allocate(maxlen)) {
    // Save a pointer to the position where the length will be stored.
    void* begin = buf.end();

    // Serialize base event.
    void* b = base::serialize(begin, t);

    // Serialize source port.
    b = event::serialize(b, sport);

    // Serialize destination port.
    b = event::serialize(b, dport);

    // Serialize transferred.
    b = event::serialize(b, transferred);

    // Serialize QTYPE.
    b = event::serialize(b, qtype);

    // Serialize domain length.
    b = event::serialize(b, domainlen);

    // Copy domain.
    b = static_cast<uint8_t*>(memcpy(b, domain, domainlen)) + domainlen;

    // Serialize number of responses.
    b = event::serialize(b, nresponses);

    // Serialize responses.
    for (size_t i = 0; i < nresponses; i++) {
      // Serialize address length.
      b = event::serialize(b, responses[i].addrlen);

      // Copy address.
      b = static_cast<uint8_t*>(
            memcpy(b, responses[i].addr, responses[i].addrlen)
          ) + responses[i].addrlen;
    }

    // Compute length.
    size_t len = static_cast<const uint8_t*>(b) -
                 static_cast<const uint8_t*>(begin);

    // Increment buffer length.
    buf.increment_length(len);

    // Store length.
    event::serialize(begin, static_cast<evlen_t>(len));

    return true;
  }

  return false;
}

void net::mon::event::dns::print_human_readable(FILE* file,
                                                printer::format fmt,
                                                const char* srchost,
                                                const char* dsthost) const
{
  base::print_human_readable(file, fmt, srchost, dsthost, sport, dport);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "  Event type: 'DNS %s'\n",
            (nresponses == 0) ? "query" : "response");

    fprintf(file, "  Query type: %u\n", qtype);

    fprintf(file, "  Domain: '%.*s'\n", domainlen, domain);

    fprintf(file, "  Transferred: %u\n", transferred);

    for (size_t i = 0, count = 0; i < nresponses; i++) {
      char ip[128];
      if (responses[i].addrlen == 4) {
        if (!inet_ntop(AF_INET, responses[i].addr, ip, sizeof(ip))) {
          continue;
        }
      } else {
        if (!inet_ntop(AF_INET6, responses[i].addr, ip, sizeof(ip))) {
          continue;
        }
      }

      fprintf(file, "  Response #%zu: '%s'\n", ++count, ip);
    }
  } else {
    fprintf(file,
            "[DNS %s] ",
            (nresponses == 0) ? "query" : "response");

    fprintf(file, "Query type: %u, ", qtype);

    fprintf(file, "domain: '%.*s', ", domainlen, domain);

    fprintf(file, "transferred: %u", transferred);

    if (nresponses > 0) {
      fprintf(file, ", response(s):");

      for (size_t i = 0, count = 0; i < nresponses; i++) {
        char ip[128];
        if (responses[i].addrlen == 4) {
          if (!inet_ntop(AF_INET, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        } else {
          if (!inet_ntop(AF_INET6, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        }

        fprintf(file, "%s '%s'", (++count > 1) ? "," : "", ip);
      }
    }
  }
}

void net::mon::event::dns::print_json(FILE* file,
                                      printer::format fmt,
                                      const char* srchost,
                                      const char* dsthost) const
{
  base::print_json(file, fmt, srchost, dsthost, sport, dport);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "    \"event-type\": \"%s\",\n",
            (nresponses == 0) ? "dns-query" : "dns-response");

    fprintf(file, "    \"query-type\": %u,\n", qtype);

    fprintf(file, "    \"domain\": \"%.*s\",\n", domainlen, domain);

    fprintf(file,
            "    \"transferred\": %u%s\n",
            transferred,
            (nresponses > 0) ? "," : "");

    if (nresponses > 0) {
      fprintf(file, "    \"responses\": [");

      for (size_t i = 0, count = 0; i < nresponses; i++) {
        char ip[128];
        if (responses[i].addrlen == 4) {
          if (!inet_ntop(AF_INET, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        } else {
          if (!inet_ntop(AF_INET6, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        }

        fprintf(file, "%s\n      \"%s\"", (++count > 1) ? "," : "", ip);
      }

      fprintf(file, "\n    ]\n");
    }
  } else {
    fprintf(file,
            "\"event-type\":\"%s\",",
            (nresponses == 0) ? "dns-query" : "dns-response");

    fprintf(file, "\"query-type\":%u,", qtype);

    fprintf(file, "\"domain\":\"%.*s\",", domainlen, domain);

    fprintf(file, "\"transferred\":%u", transferred);

    if (nresponses > 0) {
      fprintf(file, ",\"responses\":[");

      for (size_t i = 0, count = 0; i < nresponses; i++) {
        char ip[128];
        if (responses[i].addrlen == 4) {
          if (!inet_ntop(AF_INET, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        } else {
          if (!inet_ntop(AF_INET6, responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        }

        fprintf(file, "%s\"%s\"", (++count > 1) ? "," : "", ip);
      }

      fprintf(file, "]");
    }
  }
}

void net::mon::event::dns::print_csv(FILE* file,
                                     char separator,
                                     const char* srchost,
                                     const char* dsthost) const
{
  base::print_csv(file, separator, srchost, dsthost, sport, dport);

  fprintf(file,
          "%s%c",
          (nresponses == 0) ? "dns-query" : "dns-response",
          separator);

  fprintf(file, "%u%c", qtype, separator);

  fprintf(file, "%.*s%c", domainlen, domain, separator);

  fprintf(file, "%u", transferred);

  for (size_t i = 0; i < nresponses; i++) {
    char ip[128];
    if (responses[i].addrlen == 4) {
      if (!inet_ntop(AF_INET, responses[i].addr, ip, sizeof(ip))) {
        continue;
      }
    } else {
      if (!inet_ntop(AF_INET6, responses[i].addr, ip, sizeof(ip))) {
        continue;
      }
    }

    fprintf(file, "%c%s", separator, ip);
  }
}
