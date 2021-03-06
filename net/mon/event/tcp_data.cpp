#include <stdio.h>
#include <time.h>
#include "net/mon/event/tcp_data.h"

bool net::mon::event::tcp_data::build(const void* buf, size_t len)
{
  if ((base::build(buf, len)) && (size() == len)) {
    // Make 'b' point after the base event.
    const uint8_t* const b = static_cast<const uint8_t* const>(buf) +
                             base::size();

    // Extract source port.
    deserialize(sport, b);

    // Extract destination port.
    deserialize(dport, b + 2);

    // Extract creation timestamp.
    deserialize(creation, b + 4);

    // Extract payload.
    deserialize(payload, b + 12);

    return true;
  }

  return false;
}

bool net::mon::event::tcp_data::serialize(string::buffer& buf) const
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

    // Serialize creation timestamp.
    b = event::serialize(b, creation);

    // Serialize payload.
    b = event::serialize(b, payload);

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

void net::mon::event::tcp_data::print_human_readable(FILE* file,
                                                     printer::format fmt,
                                                     const char* srchost,
                                                     const char* dsthost) const
{
  base::print_human_readable(file, fmt, srchost, dsthost, sport, dport);

  time_t sec = creation / 1000000;
  suseconds_t usec = creation % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "  Event type: 'TCP data'\n");

    fprintf(file,
            "  Creation: %04u/%02u/%02u %02u:%02u:%02u.%06ld\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "  Payload: %u\n", payload);
  } else {
    fprintf(file, "[TCP data] ");

    fprintf(file,
            "Creation: %04u/%02u/%02u %02u:%02u:%02u.%06ld, ",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "Payload: %u", payload);
  }
}

void net::mon::event::tcp_data::print_json(FILE* file,
                                           printer::format fmt,
                                           const char* srchost,
                                           const char* dsthost) const
{
  base::print_json(file, fmt, srchost, dsthost, sport, dport);

  time_t sec = creation / 1000000;
  suseconds_t usec = creation % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file, "    \"event-type\": \"tcp-data\",\n");

    fprintf(file,
            "    \"creation\": \"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "    \"payload\": %u\n", payload);
  } else {
    fprintf(file, "\"event-type\":\"tcp-data\",");

    fprintf(file,
            "\"creation\":\"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "\"payload\":%u", payload);
  }
}

void net::mon::event::tcp_data::print_csv(FILE* file,
                                          char separator,
                                          const char* srchost,
                                          const char* dsthost) const
{
  base::print_csv(file, separator, srchost, dsthost, sport, dport);

  time_t sec = creation / 1000000;
  suseconds_t usec = creation % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  fprintf(file, "tcp-data%c", separator);

  fprintf(file,
          "%04u/%02u/%02u %02u:%02u:%02u.%06ld%c",
          1900 + tm.tm_year,
          1 + tm.tm_mon,
          tm.tm_mday,
          tm.tm_hour,
          tm.tm_min,
          tm.tm_sec,
          usec,
          separator);

  fprintf(file, "%u", payload);
}
