#include <stdio.h>
#include "net/mon/event/udp.h"

bool net::mon::event::udp::build(const void* buf, size_t len)
{
  if ((base::build(buf, len)) && (size() == len)) {
    // Make 'b' point after the base event.
    const uint8_t* const b = static_cast<const uint8_t* const>(buf) +
                             base::size();

    // Extract source port.
    deserialize(sport, b);

    // Extract destination port.
    deserialize(dport, b + 2);

    // Extract transferred.
    deserialize(transferred, b + 4);

    return true;
  }

  return false;
}

bool net::mon::event::udp::serialize(string::buffer& buf) const
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

void net::mon::event::udp::print_human_readable(FILE* file,
                                                printer::format fmt,
                                                const char* srchost,
                                                const char* dsthost) const
{
  base::print_human_readable(file, fmt, srchost, dsthost, sport, dport);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "  Event type: UDP\n");

    fprintf(file, "  Transferred: %u\n", transferred);
  } else {
    fprintf(file, "[UDP] ");

    fprintf(file, "Transferred: %u", transferred);
  }
}

void net::mon::event::udp::print_json(FILE* file,
                                      printer::format fmt,
                                      const char* srchost,
                                      const char* dsthost) const
{
  base::print_json(file, fmt, srchost, dsthost, sport, dport);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "    \"event-type\": \"UDP\",\n");

    fprintf(file, "    \"transferred\": %u\n", transferred);
  } else {
    fprintf(file, "\"event-type\":\"UDP\",");

    fprintf(file, "\"transferred\":%u", transferred);
  }
}

void net::mon::event::udp::print_csv(FILE* file,
                                     char separator,
                                     const char* srchost,
                                     const char* dsthost) const
{
  base::print_csv(file, separator, srchost, dsthost, sport, dport);

  fprintf(file, "UDP%c", separator);

  fprintf(file, "%u", transferred);
}
