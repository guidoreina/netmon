#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "net/mon/event/reader.h"
#include "string/buffer.h"

enum class sort_order {
  ascending,
  descending
};

typedef int (*compare)(const void*, const void*);

static bool parse_arguments(int argc,
                            const char** argv,
                            const char*& infilename,
                            const char*& outfilename,
                            compare& cmp,
                            sort_order& order);

static int process_events(const char* infilename,
                          const char* outfilename,
                          compare cmp,
                          sort_order order);

static bool write(int fd, const string::buffer& buf);

static void usage(const char* program);

static inline int compare_duration(const void* p1, const void* p2)
{
  const net::mon::event::tcp_end*
    ev1 = static_cast<const net::mon::event::tcp_end*>(p1);

  const net::mon::event::tcp_end*
    ev2 = static_cast<const net::mon::event::tcp_end*>(p2);

  uint64_t duration1 = ev1->timestamp - ev1->creation;
  uint64_t duration2 = ev2->timestamp - ev2->creation;

  if (duration1 < duration2) {
    return -1;
  } else if (duration1 > duration2) {
    return 1;
  } else {
    return 0;
  }
}

static inline int compare_transferred_client(const void* p1, const void* p2)
{
  const net::mon::event::tcp_end*
    ev1 = static_cast<const net::mon::event::tcp_end*>(p1);

  const net::mon::event::tcp_end*
    ev2 = static_cast<const net::mon::event::tcp_end*>(p2);

  if (ev1->transferred_client < ev2->transferred_client) {
    return -1;
  } else if (ev1->transferred_client > ev2->transferred_client) {
    return 1;
  } else {
    return 0;
  }
}

static inline int compare_transferred_server(const void* p1, const void* p2)
{
  const net::mon::event::tcp_end*
    ev1 = static_cast<const net::mon::event::tcp_end*>(p1);

  const net::mon::event::tcp_end*
    ev2 = static_cast<const net::mon::event::tcp_end*>(p2);

  if (ev1->transferred_server < ev2->transferred_server) {
    return -1;
  } else if (ev1->transferred_server > ev2->transferred_server) {
    return 1;
  } else {
    return 0;
  }
}

static inline int compare_transferred(const void* p1, const void* p2)
{
  const net::mon::event::tcp_end*
    ev1 = static_cast<const net::mon::event::tcp_end*>(p1);

  const net::mon::event::tcp_end*
    ev2 = static_cast<const net::mon::event::tcp_end*>(p2);

  uint64_t transferred1 = ev1->transferred_client + ev1->transferred_server;
  uint64_t transferred2 = ev2->transferred_client + ev2->transferred_server;

  if (transferred1 < transferred2) {
    return -1;
  } else if (transferred1 > transferred2) {
    return 1;
  } else {
    return 0;
  }
}

int main(int argc, const char** argv)
{
  const char* infilename;
  const char* outfilename;
  compare cmp;
  sort_order order;

  // Parse command-line arguments.
  if (parse_arguments(argc, argv, infilename, outfilename, cmp, order)) {
    return process_events(infilename, outfilename, cmp, order);
  }

  usage(argv[0]);

  return -1;
}

bool parse_arguments(int argc,
                     const char** argv,
                     const char*& infilename,
                     const char*& outfilename,
                     compare& cmp,
                     sort_order& order)
{
  // Set default values.
  infilename = nullptr;
  outfilename = nullptr;
  cmp = nullptr;
  order = sort_order::ascending;

  bool have_order = false;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--input-filename") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the input filename has not been already set...
        if (!infilename) {
          infilename = argv[i + 1];
          i += 2;
        } else {
          fprintf(stderr, "\"--input-filename\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected input filename after \"--input-filename\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--output-filename") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the output filename has not been already set...
        if (!outfilename) {
          outfilename = argv[i + 1];
          i += 2;
        } else {
          fprintf(stderr, "\"--output-filename\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected output filename after \"--output-filename\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--compare") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the compare function has not been already set...
        if (!cmp) {
          if (strcasecmp(argv[i + 1], "duration") == 0) {
            cmp = compare_duration;
          } else if (strcasecmp(argv[i + 1], "transferred-client") == 0) {
            cmp = compare_transferred_client;
          } else if (strcasecmp(argv[i + 1], "transferred-server") == 0) {
            cmp = compare_transferred_server;
          } else if (strcasecmp(argv[i + 1], "transferred") == 0) {
            cmp = compare_transferred;
          } else {
            fprintf(stderr, "Invalid compare function '%s'.\n\n", argv[i + 1]);
            return false;
          }

          i += 2;
        } else {
          fprintf(stderr, "\"--compare\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr, "Expected compare function after \"--compare\".\n\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--order") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the sort order has not been already set...
        if (!have_order) {
          if (strcasecmp(argv[i + 1], "ascending") == 0) {
            order = sort_order::ascending;
          } else if (strcasecmp(argv[i + 1], "descending") == 0) {
            order = sort_order::descending;
          } else {
            fprintf(stderr, "Invalid sort order '%s'.\n\n", argv[i + 1]);
            return false;
          }

          have_order = true;
          i += 2;
        } else {
          fprintf(stderr, "\"--order\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr, "Expected sort order after \"--order\".\n\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--help") == 0) {
      return false;
    } else {
      fprintf(stderr, "Invalid option \"%s\".\n\n", argv[i]);
      return false;
    }
  }

  if ((infilename) && (outfilename) && (cmp)) {
    return true;
  } else if (argc > 1) {
    fprintf(stderr, "Mandatory arguments missing.\n");
  }

  return false;
}

int process_events(const char* infilename,
                   const char* outfilename,
                   compare cmp,
                   sort_order order)
{
  // Open event file.
  net::mon::event::reader evreader;
  if (evreader.open(infilename)) {
    // Open output file.
    int fd;
    if ((fd = open(outfilename, O_CREAT | O_TRUNC | O_WRONLY, 0644)) != -1) {
      net::mon::event::file::header header;
      header.timestamp.first = ULLONG_MAX;
      header.timestamp.last = 0;

      string::buffer inbuf;
      size_t nevents = 0;

      // Read events.
      const void* event;
      size_t len;
      while (evreader.next(event, len, header.timestamp.last)) {
        // TCP end?
        net::mon::event::tcp_end tcp_end;
        if ((net::mon::event::base::extract_type(event) ==
             net::mon::event::type::tcp_end) &&
            (tcp_end.build(event, len))) {
          if (inbuf.append(reinterpret_cast<const char*>(&tcp_end),
                           sizeof(net::mon::event::tcp_end))) {
            if (tcp_end.timestamp < header.timestamp.first) {
              header.timestamp.first = tcp_end.timestamp;
            }

            nevents++;
          } else {
            fprintf(stderr, "Error allocating memory.\n");

            close(fd);
            unlink(outfilename);

            return -1;
          }
        }
      }

      // Sort events.
      qsort(inbuf.data(), nevents, sizeof(net::mon::event::tcp_end), cmp);

      const net::mon::event::tcp_end* const
        events = reinterpret_cast<const net::mon::event::tcp_end*>(
                   inbuf.data()
                 );

      // Serialize events.
      string::buffer outbuf;
      for (size_t i = 0; i < nevents; i++) {
        size_t idx = (order == sort_order::ascending) ? i : nevents - 1 - i;

        // Serialize event.
        if (!events[idx].serialize(outbuf)) {
          fprintf(stderr, "Error allocating memory.\n");

          close(fd);
          unlink(outfilename);

          return -1;
        }
      }

      uint8_t buf[net::mon::event::file::header::size];
      header.serialize(buf, sizeof(buf));

      if ((write(fd, buf, sizeof(buf)) == static_cast<ssize_t>(sizeof(buf))) &&
          (write(fd, outbuf))) {
        close(fd);

        return 0;
      } else {
        fprintf(stderr, "Error writing to file.\n");

        close(fd);
        unlink(outfilename);
      }
    } else {
      fprintf(stderr, "Error opening output file '%s'.\n", outfilename);
    }
  } else {
    fprintf(stderr, "Error opening event file '%s'.\n", infilename);
  }

  return -1;
}

bool write(int fd, const string::buffer& buf)
{
  const char* ptr = buf.data();
  size_t written = 0;

  while (written < buf.length()) {
    ssize_t ret;
    if ((ret = ::write(fd, ptr, buf.length() - written)) > 0) {
      if ((written += ret) == buf.length()) {
        return true;
      }

      ptr += ret;
    } else if (ret < 0) {
      if (errno != EINTR) {
        return false;
      }
    }
  }

  return true;
}

void usage(const char* program)
{
  fprintf(stderr,
          "Usage: %s [OPTIONS] --input-filename <filename> "
          "--output-filename <filename>\n",
          program);

  fprintf(stderr, "\n");

  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  --help\n");

  fprintf(stderr, "  --compare <compare-function>\n");
  fprintf(stderr,
          "    <compare-function> ::= \"duration\" | \"transferred-client\" | "
          "\"transferred-server\" | \"transferred\"\n");

  fprintf(stderr, "  --order <sort-order>\n");
  fprintf(stderr, "    <sort-order> ::= \"ascending\" | \"descending\"\n");
  fprintf(stderr, "    Default: \"ascending\"\n");

  fprintf(stderr, "\n");
}
