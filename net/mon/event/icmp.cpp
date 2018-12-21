#include <stdio.h>
#include "net/mon/event/icmp.h"

bool net::mon::event::icmp::build(const void* buf, size_t len)
{
  if ((base::build(buf, len)) && (size() == len)) {
    // Make 'b' point after the base event.
    const uint8_t* const b = static_cast<const uint8_t* const>(buf) +
                             base::size();

    // Extract ICMP type.
    icmp_type = *b;

    // Extract ICMP code.
    icmp_code = b[1];

    // Extract transferred.
    deserialize(transferred, b + 2);

    return true;
  }

  return false;
}

bool net::mon::event::icmp::serialize(string::buffer& buf) const
{
  // Allocate memory for the event.
  if (buf.allocate(maxlen)) {
    // Save a pointer to the position where the length will be stored.
    void* begin = buf.end();

    // Serialize base event.
    void* b = base::serialize(begin, t);

    // Serialize ICMP type.
    b = event::serialize(b, icmp_type);

    // Serialize ICMP code.
    b = event::serialize(b, icmp_code);

    // Serialize transferred.
    b = event::serialize(b, transferred);

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

void net::mon::event::icmp::print_human_readable(FILE* file,
                                                 printer::format fmt,
                                                 const char* srchost,
                                                 const char* dsthost) const
{
  base::print_human_readable(file, fmt, srchost, dsthost);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "  Event type: ICMP\n");

    fprintf(file, "  ICMP type: %u\n", icmp_type);

    fprintf(file, "  ICMP code: %u\n", icmp_code);

    fprintf(file, "  Transferred: %u\n", transferred);
  } else {
    fprintf(file, "[ICMP] ");

    fprintf(file, "ICMP type: %u, ", icmp_type);

    fprintf(file, "ICMP code: %u, ", icmp_code);

    fprintf(file, "transferred: %u", transferred);
  }
}

void net::mon::event::icmp::print_json(FILE* file,
                                       printer::format fmt,
                                       const char* srchost,
                                       const char* dsthost) const
{
  base::print_json(file, fmt, srchost, dsthost);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "    \"event-type\": \"ICMP\",\n");

    fprintf(file, "    \"icmp-type\": %u,\n", icmp_type);

    fprintf(file, "    \"icmp-code\": %u,\n", icmp_code);

    fprintf(file, "    \"transferred\": %u\n", transferred);
  } else {
    fprintf(file, "\"event-type\":\"ICMP\",");

    fprintf(file, "\"icmp-type\":%u,", icmp_type);

    fprintf(file, "\"icmp-code\":%u,", icmp_code);

    fprintf(file, "\"transferred\":%u", transferred);
  }
}

void net::mon::event::icmp::print_csv(FILE* file,
                                      char separator,
                                      const char* srchost,
                                      const char* dsthost) const
{
  base::print_csv(file, separator, srchost, dsthost);

  fprintf(file, "ICMP%c", separator);

  fprintf(file, "%u%c", icmp_type, separator);

  fprintf(file, "%u%c", icmp_code, separator);

  fprintf(file, "%u", transferred);
}
