#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include "net/mon/event/base.h"

bool net::mon::event::base::build(const void* buf, size_t len)
{
  // Precondition: len >= minlen.

  // Make 'b' point to the beginning of the event.
  const uint8_t* b = static_cast<const uint8_t*>(buf);

  // Extract address length.
  switch (addrlen = b[sizeof(evlen_t) + 8 + sizeof(type)]) {
    case 16:
      if (len < size()) {
        return false;
      }

      // Fall through.
    case 4:
      // Extract timestamp.
      timestamp = extract_timestamp(b);

      // Make 'b' point to the source address.
      b += (sizeof(evlen_t) + 8 + sizeof(type) + 1);

      // Copy source address.
      memcpy(saddr, b, addrlen);

      // Skip source address.
      b += addrlen;

      // Copy destination address.
      memcpy(daddr, b, addrlen);

      return true;
    default:
      return false;
  }
}

void net::mon::event::base::print_human_readable(FILE* file,
                                                 printer::format fmt,
                                                 const char* srchost,
                                                 const char* dsthost) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "  Date: %04u/%02u/%02u %02u:%02u:%02u.%06ld\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    if (!srchost) {
      fprintf(file,
              "  Source: %s%s%s\n",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "");
    } else {
      fprintf(file,
              "  Source: %s%s%s (%s)\n",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "",
              srchost);
    }

    if (!dsthost) {
      fprintf(file,
              "  Destination: %s%s%s\n",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "");
    } else {
      fprintf(file,
              "  Destination: %s%s%s (%s)\n",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "",
              dsthost);
    }
  } else {
    fprintf(file,
            "[%04u/%02u/%02u %02u:%02u:%02u.%06ld] ",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    if (!srchost) {
      fprintf(file, "[%s] -> ", src);
    } else {
      fprintf(file, "[%s] (%s) -> ", src, srchost);
    }

    if (!dsthost) {
      fprintf(file, "[%s] ", dst);
    } else {
      fprintf(file, "[%s] (%s) ", dst, dsthost);
    }
  }
}

void net::mon::event::base::print_human_readable(FILE* file,
                                                 printer::format fmt,
                                                 const char* srchost,
                                                 const char* dsthost,
                                                 in_port_t sport,
                                                 in_port_t dport) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "  Date: %04u/%02u/%02u %02u:%02u:%02u.%06ld\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    if (!srchost) {
      fprintf(file,
              "  Source: %s%s%s:%u\n",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "",
              ntohs(sport));
    } else {
      fprintf(file,
              "  Source: %s%s%s:%u (%s)\n",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "",
              ntohs(sport),
              srchost);
    }

    if (!dsthost) {
      fprintf(file,
              "  Destination: %s%s%s:%u\n",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "",
              ntohs(dport));
    } else {
      fprintf(file,
              "  Destination: %s%s%s:%u (%s)\n",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "",
              ntohs(dport),
              dsthost);
    }
  } else {
    fprintf(file,
            "[%04u/%02u/%02u %02u:%02u:%02u.%06ld] ",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    if (!srchost) {
      fprintf(file,
              "%s%s%s:%u -> ",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "",
              ntohs(sport));
    } else {
      fprintf(file,
              "%s%s%s:%u (%s) -> ",
              (addrlen == 16) ? "[" : "",
              src,
              (addrlen == 16) ? "]" : "",
              ntohs(sport),
              srchost);
    }

    if (!dsthost) {
      fprintf(file,
              "%s%s%s:%u ",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "",
              ntohs(dport));
    } else {
      fprintf(file,
              "%s%s%s:%u (%s) ",
              (addrlen == 16) ? "[" : "",
              dst,
              (addrlen == 16) ? "]" : "",
              ntohs(dport),
              dsthost);
    }
  }
}

void net::mon::event::base::print_json(FILE* file,
                                       printer::format fmt,
                                       const char* srchost,
                                       const char* dsthost) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "    \"date\": \"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "    \"source-ip\": \"%s\",\n", src);

    if (srchost) {
      fprintf(file, "    \"source-hostname\": \"%s\",\n", srchost);
    }

    fprintf(file, "    \"destination-ip\": \"%s\",\n", dst);

    if (dsthost) {
      fprintf(file, "    \"destination-hostname\": \"%s\",\n", dsthost);
    }
  } else {
    fprintf(file,
            "\"date\":\"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "\"source-ip\":\"%s\",", src);

    if (srchost) {
      fprintf(file, "\"source-hostname\":\"%s\",", srchost);
    }

    fprintf(file, "\"destination-ip\":\"%s\",", dst);

    if (dsthost) {
      fprintf(file, "\"destination-hostname\":\"%s\",", dsthost);
    }
  }
}

void net::mon::event::base::print_json(FILE* file,
                                       printer::format fmt,
                                       const char* srchost,
                                       const char* dsthost,
                                       in_port_t sport,
                                       in_port_t dport) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

  if (fmt == printer::format::pretty_print) {
    fprintf(file,
            "    \"date\": \"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "    \"source-ip\": \"%s\",\n", src);

    if (srchost) {
      fprintf(file, "    \"source-hostname\": \"%s\",\n", srchost);
    }

    fprintf(file, "    \"source-port\": %u,\n", ntohs(sport));

    fprintf(file, "    \"destination-ip\": \"%s\",\n", dst);

    if (dsthost) {
      fprintf(file, "    \"destination-hostname\": \"%s\",\n", dsthost);
    }

    fprintf(file, "    \"destination-port\": %u,\n", ntohs(dport));
  } else {
    fprintf(file,
            "\"date\":\"%04u/%02u/%02u %02u:%02u:%02u.%06ld\",",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            usec);

    fprintf(file, "\"source-ip\":\"%s\",", src);

    if (srchost) {
      fprintf(file, "\"source-hostname\":\"%s\",", srchost);
    }

    fprintf(file, "\"source-port\":%u,", ntohs(sport));

    fprintf(file, "\"destination-ip\":\"%s\",", dst);

    if (dsthost) {
      fprintf(file, "\"destination-hostname\":\"%s\",", dsthost);
    }

    fprintf(file, "\"destination-port\":%u,", ntohs(dport));
  }
}

void net::mon::event::base::print_csv(FILE* file,
                                      char separator,
                                      const char* srchost,
                                      const char* dsthost) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

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

  fprintf(file, "%s%c", src, separator);
  fprintf(file, "%s%c", srchost ? srchost : "", separator);

  // Leave space for the source port.
  fprintf(file, "%c", separator);

  fprintf(file, "%s%c", dst, separator);
  fprintf(file, "%s%c", dsthost ? dsthost : "", separator);

  // Leave space for the destination port.
  fprintf(file, "%c", separator);
}

void net::mon::event::base::print_csv(FILE* file,
                                      char separator,
                                      const char* srchost,
                                      const char* dsthost,
                                      in_port_t sport,
                                      in_port_t dport) const
{
  char src[128];
  char dst[128];

  if (addrlen == 4) {
    if ((!inet_ntop(AF_INET, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET, daddr, dst, sizeof(dst)))) {
      return;
    }
  } else {
    if ((!inet_ntop(AF_INET6, saddr, src, sizeof(src))) ||
        (!inet_ntop(AF_INET6, daddr, dst, sizeof(dst)))) {
      return;
    }
  }

  time_t sec = timestamp / 1000000;
  suseconds_t usec = timestamp % 1000000;

  struct tm tm;
  localtime_r(&sec, &tm);

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

  fprintf(file, "%s%c", src, separator);
  fprintf(file, "%s%c", srchost ? srchost : "", separator);
  fprintf(file, "%u%c", ntohs(sport), separator);

  fprintf(file, "%s%c", dst, separator);
  fprintf(file, "%s%c", dsthost ? dsthost : "", separator);
  fprintf(file, "%u%c", ntohs(dport), separator);
}
