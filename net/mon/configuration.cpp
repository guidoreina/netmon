#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <net/if.h>
#include "net/mon/configuration.h"
#include "net/capture/limits.h"
#include "util/parser/number.h"
#include "util/parser/size.h"

bool net::mon::configuration::capture::ring_buffer::valid() const
{
  if ((block_size < net::capture::ring_buffer::min_block_size) ||
      (block_size > net::capture::ring_buffer::max_block_size)) {
    fprintf(stderr,
            "Block size (%zu) not in the range %zu .. %zu.\n\n",
            block_size,
            net::capture::ring_buffer::min_block_size,
            net::capture::ring_buffer::max_block_size);

    return false;
  }

  if ((frame_size < net::capture::ring_buffer::min_frame_size) ||
      (frame_size > net::capture::ring_buffer::max_frame_size)) {
    fprintf(stderr,
            "Frame size (%zu) not in the range %zu .. %zu.\n\n",
            frame_size,
            net::capture::ring_buffer::min_frame_size,
            net::capture::ring_buffer::max_frame_size);

    return false;
  }

  if (frame_size > block_size) {
    fprintf(stderr,
            "Frame size (%zu) must be smaller or equal than the block size "
            "(%zu).\n\n",
            frame_size,
            block_size);

    return false;
  }

  if ((frame_count < net::capture::ring_buffer::min_frames) ||
      (frame_count > net::capture::ring_buffer::max_frames)) {
    fprintf(stderr,
            "Number of frames (%zu) not in the range %zu .. %zu.\n\n",
            frame_count,
            net::capture::ring_buffer::min_frames,
            net::capture::ring_buffer::max_frames);

    return false;
  }

  return true;
}

void net::mon::configuration::capture::ring_buffer::print() const
{
  printf("Ring buffer configuration:\n");

  printf("  Block size: %zu.\n", block_size);
  printf("  Frame size: %zu.\n", frame_size);
  printf("  Number of frames: %zu.\n", frame_count);

  // Calculate number of blocks.
  size_t block_count = frame_count / (block_size / frame_size);

  printf("  Ring buffer size: %zu.\n", block_count * block_size);

  printf("\n");
}

void net::mon::configuration::capture::ring_buffer::help()
{
  fprintf(stderr, "  Ring buffer configuration:\n");
  fprintf(stderr,
          "    --ring-buffer-block-size <size>\n"
          "      <size>: size of the ring buffer block.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n\n",
          net::capture::ring_buffer::min_block_size,
          net::capture::ring_buffer::max_block_size,
          net::capture::ring_buffer::default_block_size);

  fprintf(stderr,
          "    --ring-buffer-frame-size <size>\n"
          "      <size>: size of the ring buffer frame.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n\n",
          net::capture::ring_buffer::min_frame_size,
          net::capture::ring_buffer::max_frame_size,
          net::capture::ring_buffer::default_frame_size);

  fprintf(stderr,
          "    --ring-buffer-frame-count <number>\n"
          "      <number>: number of frames in the ring buffer.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n",
          net::capture::ring_buffer::min_frames,
          net::capture::ring_buffer::max_frames,
          net::capture::ring_buffer::default_frames);

  fprintf(stderr, "\n\n");
}

bool net::mon::configuration::capture::valid() const
{
  if (device) {
    switch (m) {
      case method::pcap:
        return true;
      case method::ring_buffer:
      case method::socket:
        if (ifindex > 0) {
          if ((rcvbuf_size == 0) ||
              (rcvbuf_size >= net::capture::min_rcvbuf_size)) {
            return (m == method::ring_buffer) ? rb.valid() : true;
          } else {
            fprintf(stderr,
                    "Invalid size of the socket receive buffer %d.\n\n",
                    rcvbuf_size);
          }
        } else {
          fprintf(stderr, "Unknown network interface '%s'.\n\n", device);
        }

        break;
      case method::none:
        fprintf(stderr, "Capture method not set.\n\n");
    }
  } else {
    fprintf(stderr, "Capture device not set.\n\n");
  }

  return false;
}

void net::mon::configuration::capture::print() const
{
  printf("Capture configuration:\n");

  switch (m) {
    case method::none:
      printf("  Capture method not set.\n");
      break;
    case method::pcap:
      printf("  Capture method: \"pcap\".\n");
      break;
    case method::ring_buffer:
      printf("  Capture method: \"ring-buffer\".\n");
      break;
    case method::socket:
      printf("  Capture method: \"socket\".\n");
      break;
  }

  if (device) {
    printf("  Capture device: \"%s\".\n", device);
  } else {
    printf("  Capture device not set.\n");
  }

  switch (m) {
    case method::none:
    case method::pcap:
      break;
    case method::ring_buffer:
    case method::socket:
      if (rcvbuf_size != 0) {
        printf("  Size of the socket receive buffer: %d.\n", rcvbuf_size);
      }

      printf("  Promiscuous mode? %s.\n", promiscuous_mode ? "yes" : "no");
      break;
  }

  printf("\n");

  if (m == method::ring_buffer) {
    rb.print();
  }
}

void net::mon::configuration::capture::help()
{
  fprintf(stderr, "  Capture configuration:\n");
  fprintf(stderr,
          "    --capture-method <method>\n"
          "      <method> ::= \"pcap\" | \"ring-buffer\" | \"socket\"\n"
          "      Mandatory.\n\n");

  fprintf(stderr,
          "    --capture-device <device>\n"
          "      <device>: either a PCAP filename for the capture method "
          "\"pcap\" or\n"
          "                the name of a network interface.\n"
          "      Mandatory.\n\n");

  fprintf(stderr,
          "    --rcvbuf-size <size>\n"
          "      <size>: size of the socket receive buffer.\n"
          "      Greater or equal than: %d, default: not set.\n"
          "      Optional.\n\n",
          net::capture::min_rcvbuf_size);

  fprintf(stderr,
          "    --promiscuous-mode\n"
          "      Enable interface's promiscuous mode.\n"
          "      Default: no.\n"
          "      Optional.\n");

  fprintf(stderr, "\n\n");

  ring_buffer::help();
}

template<typename Connection>
bool net::mon::configuration::tcp<Connection>::valid() const
{
  if ((size < connections_type::min_size) ||
      (size > connections_type::max_size)) {
    fprintf(stderr,
            "Hash table size (%zu) not in the range %zu .. %zu.\n\n",
            size,
            connections_type::min_size,
            connections_type::max_size);

    return false;
  }

  if ((size & (size - 1)) != 0) {
    fprintf(stderr, "Hash table size (%zu) must be a power of 2.\n\n", size);
    return false;
  }

  if ((maxconns < connections_type::min_connections) ||
      (maxconns > connections_type::max_connections)) {
    fprintf(stderr,
            "Maximum number of connections (%zu) not in the range %zu .. %zu."
            "\n\n",
            maxconns,
            connections_type::min_connections,
            connections_type::max_connections);

    return false;
  }

  if (timeout < connections_type::min_timeout) {
    fprintf(stderr,
            "Connection timeout (%" PRIu64 ") must be greater or equal than %"
            PRIu64 ".\n\n",
            timeout,
            connections_type::min_timeout);

    return false;
  }

  if (time_wait < connections_type::min_time_wait) {
    fprintf(stderr,
            "TCP time wait (%" PRIu64 ") must be greater or equal than %" PRIu64
            ".\n\n",
            time_wait,
            connections_type::min_time_wait);

    return false;
  }

  return true;
}

template<typename Connection>
void net::mon::configuration::tcp<Connection>::print() const
{
  printf("TCP/IPv%u hash table configuration:\n",
         (sizeof(typename connections_type::address_type) ==
          sizeof(struct in_addr)) ? 4 : 6);

  printf("  Hash table size: %zu.\n", size);
  printf("  Maximum number of connections: %zu.\n", maxconns);
  printf("  Connection timeout: %" PRIu64 ".\n", timeout);
  printf("  TCP time wait: %" PRIu64 ".\n", time_wait);

  printf("\n");
}

template<typename Connection>
void net::mon::configuration::tcp<Connection>::help()
{
  unsigned ip_version =
           (sizeof(typename connections_type::address_type) ==
            sizeof(struct in_addr)) ? 4 : 6;

  fprintf(stderr, "  TCP/IPv%u hash table configuration:\n", ip_version);

  fprintf(stderr,
          "    --tcp-ipv%u-hash-size <number>\n"
          "      <number>: size of the hash table.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n\n",
          ip_version,
          connections_type::min_size,
          connections_type::max_size,
          connections_type::default_size);

  fprintf(stderr,
          "    --tcp-ipv%u-max-connections <number>\n"
          "      <number>: maximum number of connections.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n\n",
          ip_version,
          connections_type::min_connections,
          connections_type::max_connections,
          connections_type::default_max_connections);

  fprintf(stderr,
          "    --connection-timeout <number>\n"
          "      <number>: connection timeout (seconds).\n"
          "      Greater or equal than: %" PRIu64 ", default: %" PRIu64 ".\n"
          "      Optional.\n\n",
          connections_type::min_timeout,
          connections_type::default_timeout);

  fprintf(stderr,
          "    --tcp-time-wait <number>\n"
          "      <number>: TCP time wait (seconds).\n"
          "      Greater or equal than: %" PRIu64 ", default: %" PRIu64 ".\n"
          "      Optional.\n",
          connections_type::min_time_wait,
          connections_type::default_time_wait);

  fprintf(stderr, "\n\n");
}

bool net::mon::configuration::parse(size_t argc, const char** argv)
{
  using namespace util::parser;

  bool have_block_size = false;
  bool have_frame_size = false;
  bool have_frame_count = false;

  bool have_tcp4_size = false;
  bool have_tcp4_maxconns = false;
  bool have_tcp6_size = false;
  bool have_tcp6_maxconns = false;

  bool have_timeout = false;
  bool have_time_wait = false;

  bool have_file_allocation_size = false;
  bool have_buffer_size = false;

  size_t i = 1;
  while (i < argc) {
    ////////////////////////////////////
    //                                //
    // Capture configuration.         //
    //                                //
    ////////////////////////////////////

    if (strcasecmp(argv[i], "--capture-method") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the capture method has not been already set...
        if (cap.m == capture::method::none) {
          if (strcasecmp(argv[i + 1], "pcap") == 0) {
            cap.m = capture::method::pcap;
          } else if (strcasecmp(argv[i + 1], "ring-buffer") == 0) {
            cap.m = capture::method::ring_buffer;
          } else if (strcasecmp(argv[i + 1], "socket") == 0) {
            cap.m = capture::method::socket;
          } else {
            fprintf(stderr, "Invalid capture method '%s'.\n\n", argv[i + 1]);
            return false;
          }

          i += 2;
        } else {
          fprintf(stderr, "\"--capture-method\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected capture method after \"--capture-method\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--capture-device") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the capture device has not been already set...
        if (!cap.device) {
          cap.device = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr, "\"--capture-device\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected capture device after \"--capture-device\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--rcvbuf-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the size of the socket receive buffer has not been already set...
        if (cap.rcvbuf_size == 0) {
          uint64_t n;
          if (size::parse(argv[i + 1],
                          n,
                          net::capture::min_rcvbuf_size,
                          INT_MAX)) {
            cap.rcvbuf_size = static_cast<int>(n);

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid size of the socket receive buffer '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr, "\"--rcvbuf-size\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected size of the socket receive buffer after "
                "\"--rcvbuf-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--promiscuous-mode") == 0) {
      // If the promiscuous mode has not been already set...
      if (!cap.promiscuous_mode) {
        cap.promiscuous_mode = true;

        i++;
      } else {
        fprintf(stderr, "\"--promiscuous-mode\" appears more than once.\n\n");
        return false;
      }

    ////////////////////////////////////
    //                                //
    // Ring buffer configuration.     //
    //                                //
    ////////////////////////////////////

    } else if (strcasecmp(argv[i], "--ring-buffer-block-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the block size has not been already set...
        if (!have_block_size) {
          if (size::parse(argv[i + 1],
                          cap.rb.block_size,
                          net::capture::ring_buffer::min_block_size,
                          net::capture::ring_buffer::max_block_size)) {
            have_block_size = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid ring buffer block size '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--ring-buffer-block-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected ring buffer block size after "
                "\"--ring-buffer-block-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--ring-buffer-frame-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the frame size has not been already set...
        if (!have_frame_size) {
          if (size::parse(argv[i + 1],
                          cap.rb.frame_size,
                          net::capture::ring_buffer::min_frame_size,
                          net::capture::ring_buffer::max_frame_size)) {
            cap.rb.frame_size = TPACKET_ALIGN(cap.rb.frame_size);

            have_frame_size = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid ring buffer frame size '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--ring-buffer-frame-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected ring buffer frame size after "
                "\"--ring-buffer-frame-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--ring-buffer-frame-count") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the frame count has not been already set...
        if (!have_frame_count) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            net::capture::ring_buffer::min_frames,
                            net::capture::ring_buffer::max_frames)) {
            cap.rb.frame_count = static_cast<size_t>(n);

            have_frame_count = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid ring buffer frame count '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--ring-buffer-frame-count\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected ring buffer frame count after "
                "\"--ring-buffer-frame-count\".\n\n");

        return false;
      }

    ////////////////////////////////////
    //                                //
    // TCP/IPv4 configuration.        //
    //                                //
    ////////////////////////////////////

    } else if (strcasecmp(argv[i], "--tcp-ipv4-hash-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the size has not been already set...
        if (!have_tcp4_size) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            tcp4_type::connections_type::min_size,
                            tcp4_type::connections_type::max_size)) {
            tcp4.size = static_cast<size_t>(n);

            have_tcp4_size = true;

            i += 2;
          } else {
            fprintf(stderr, "Invalid hash table size '%s'.\n\n", argv[i + 1]);
            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--tcp-ipv4-hash-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected hash table size after \"--tcp-ipv4-hash-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--tcp-ipv4-max-connections") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the maximum number of connections has not been already set...
        if (!have_tcp4_maxconns) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            tcp4_type::connections_type::min_connections,
                            tcp4_type::connections_type::max_connections)) {
            tcp4.maxconns = static_cast<size_t>(n);

            have_tcp4_maxconns = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid maximum number of connections '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--tcp-ipv4-max-connections\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected maximum number of connections after "
                "\"--tcp-ipv4-max-connections\".\n\n");

        return false;
      }

    ////////////////////////////////////
    //                                //
    // TCP/IPv6 configuration.        //
    //                                //
    ////////////////////////////////////

    } else if (strcasecmp(argv[i], "--tcp-ipv6-hash-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the size has not been already set...
        if (!have_tcp6_size) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            tcp6_type::connections_type::min_size,
                            tcp6_type::connections_type::max_size)) {
            tcp6.size = static_cast<size_t>(n);

            have_tcp6_size = true;

            i += 2;
          } else {
            fprintf(stderr, "Invalid hash table size '%s'.\n\n", argv[i + 1]);
            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--tcp-ipv6-hash-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected hash table size after \"--tcp-ipv6-hash-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--tcp-ipv6-max-connections") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the maximum number of connections has not been already set...
        if (!have_tcp6_maxconns) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            tcp6_type::connections_type::min_connections,
                            tcp6_type::connections_type::max_connections)) {
            tcp6.maxconns = static_cast<size_t>(n);

            have_tcp6_maxconns = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid maximum number of connections '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--tcp-ipv6-max-connections\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected maximum number of connections after "
                "\"--tcp-ipv6-max-connections\".\n\n");

        return false;
      }

    ////////////////////////////////////
    //                                //
    // TCP/IP configuration.          //
    //                                //
    ////////////////////////////////////

    } else if (strcasecmp(argv[i], "--connection-timeout") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the connection timeout has not been already set...
        if (!have_timeout) {
          if (number::parse(argv[i + 1],
                            tcp4.timeout,
                            tcp4_type::connections_type::min_timeout)) {
            tcp6.timeout = tcp4.timeout;

            have_timeout = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid connection timeout '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--connection-timeout\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected connection timeout after "
                "\"--connection-timeout\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--tcp-time-wait") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the TCP time wait has not been already set...
        if (!have_time_wait) {
          if (number::parse(argv[i + 1],
                            tcp4.time_wait,
                            tcp4_type::connections_type::min_time_wait)) {
            tcp6.time_wait = tcp4.time_wait;

            have_time_wait = true;

            i += 2;
          } else {
            fprintf(stderr, "Invalid TCP time wait '%s'.\n\n", argv[i + 1]);
            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--tcp-time-wait\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected TCP time wait after \"--tcp-time-wait\".\n\n");

        return false;
      }

    ////////////////////////////////////
    //                                //
    // Network monitor configuration. //
    //                                //
    ////////////////////////////////////

    } else if (strcasecmp(argv[i], "--number-workers") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the number of workers has not been already set...
        if (nworkers == 0) {
          uint64_t n;
          if (number::parse(argv[i + 1],
                            n,
                            workers::min_workers,
                            workers::max_workers)) {
            nworkers = static_cast<size_t>(n);

            i += 2;
          } else {
            fprintf(stderr, "Invalid number of workers '%s'.\n\n", argv[i + 1]);
            return false;
          }
        } else {
          fprintf(stderr, "Number of workers has been already set.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected number of workers after \"--number-workers\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--processors") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the number of workers has not been already set...
        if (nworkers == 0) {
          size_t min = (_M_nprocessors < workers::max_workers) ?
                         _M_nprocessors : workers::max_workers;

          if (strcasecmp(argv[i + 1], "all") == 0) {
            for (size_t i = 0; i < min; i++) {
              processors[nworkers++] = i;
            }
          } else if (strcasecmp(argv[i + 1], "even") == 0) {
            for (size_t i = 0; i < min; i += 2) {
              processors[nworkers++] = i;
            }
          } else if (strcasecmp(argv[i + 1], "odd") == 0) {
            for (size_t i = 1; i < min; i += 2) {
              processors[nworkers++] = i;
            }
          } else {
            if (!parse_number_list(argv[i + 1],
                                   workers::min_workers,
                                   workers::max_workers,
                                   0,
                                   _M_nprocessors - 1,
                                   nworkers,
                                   processors)) {
              fprintf(stderr, "Invalid processor list '%s'.\n\n", argv[i + 1]);
              return false;
            }
          }

          i += 2;
        } else {
          fprintf(stderr, "Number of workers has been already set.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected processor list after \"--processors\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--events-directory") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the events directory has not been already set...
        if (!_M_evdir) {
          _M_evdir = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr, "\"--events-directory\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected events directory after \"--events-directory\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--file-allocation-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the file allocation size has not been already set...
        if (!have_file_allocation_size) {
          if (size::parse(argv[i + 1], file_allocation_size)) {
            have_file_allocation_size = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid file allocation size '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--file-allocation-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected file allocation size after "
                "\"--file-allocation-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--event-writer-buffer-size") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the size of the event writer buffer has not been already set...
        if (!have_buffer_size) {
          if (size::parse(argv[i + 1],
                          buffer_size,
                          event::writer::min_buffer_size)) {
            have_buffer_size = true;

            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid size of the event writer buffer '%s'.\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr,
                  "\"--event-writer-buffer-size\" appears more than once.\n\n");

          return false;
        }
      } else {
        fprintf(stderr,
                "Expected size of the event writer buffer after "
                "\"--event-writer-buffer-size\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--help") == 0) {
      return false;
    } else {
      fprintf(stderr, "Invalid option \"%s\".\n\n", argv[i]);
      return false;
    }
  }

  switch (cap.m) {
    case capture::method::pcap:
    case capture::method::none:
      break;
    case capture::method::ring_buffer:
    case capture::method::socket:
      if (cap.device) {
        cap.ifindex = if_nametoindex(cap.device);
      }

      break;
  }

  if (argc > 1) {
    if (nworkers == 0) {
      nworkers = workers::default_workers;
    }

    if (!_M_evdir) {
      _M_evdir = worker::default_directory;
    }

    size_t len;
    if ((len = strlen(_M_evdir)) >= sizeof(evdir)) {
      fprintf(stderr, "Directory name \"%s\" is too long.\n\n", _M_evdir);
      return false;
    }

    struct stat sbuf;
    if (stat(_M_evdir, &sbuf) < 0) {
      fprintf(stderr, "Directory \"%s\" doesn't exist.\n\n", _M_evdir);
      return false;
    }

    if (!S_ISDIR(sbuf.st_mode)) {
      fprintf(stderr, "\"%s\" is not a directory.\n\n", _M_evdir);
      return false;
    }

    if (valid()) {
      // Remove trailing '/' (if any).
      while ((len > 0) && (_M_evdir[len - 1] == '/')) {
        len--;
      }

      if (len > 0) {
        memcpy(evdir, _M_evdir, len);
      }

      evdir[len] = 0;

      return true;
    }
  }

  return false;
}

bool net::mon::configuration::valid() const
{
  if ((nworkers < workers::min_workers) || (nworkers > workers::max_workers)) {
    fprintf(stderr,
            "Number of workers (%zu) not in the range %zu .. %zu.\n\n",
            nworkers,
            workers::min_workers,
            workers::max_workers);

    return false;
  }

  if (buffer_size < event::writer::min_buffer_size) {
    fprintf(stderr,
            "Size of the event writer buffer (%zu) must be greater or equal "
            "than %zu.\n\n",
            buffer_size,
            event::writer::min_buffer_size);

    return false;
  }

  return ((cap.valid()) && (tcp4.valid()) && (tcp6.valid()));
}

void net::mon::configuration::print() const
{
  cap.print();
  tcp4.print();
  tcp6.print();

  printf("Workers configuration:\n");

  printf("  Number of workers: %zu.\n", nworkers);

  // If processors have been defined...
  if (processors[0] != worker::no_processor) {
    printf("  Processor%s:", (nworkers != 1) ? "s" : "");

    for (size_t i = 0; i < nworkers; i++) {
      printf("%s #%zu", (i > 0) ? "," : "", processors[i]);
    }

    printf("\n");
  }

  printf("  Events directory: \"%s/\".\n", evdir);
  printf("  File allocation size: %" PRIu64 ".\n", file_allocation_size);
  printf("  Size of the event writer buffer: %zu.\n", buffer_size);

  printf("\n");
}

void net::mon::configuration::help(const char* program)
{
  fprintf(stderr, "%s OPTIONS\n\n", program);

  fprintf(stderr, "OPTIONS:\n");

  capture::help();
  tcp4_type::help();
  tcp6_type::help();

  fprintf(stderr, "  Workers configuration:\n");
  fprintf(stderr,
          "    --number-workers <number>\n"
          "      <number>: number of worker threads.\n"
          "      Range: %zu .. %zu, default: %zu.\n"
          "      Optional.\n\n",
          workers::min_workers,
          workers::max_workers,
          workers::default_workers);

  fprintf(stderr,
          "    --processors \"all\" | \"even\" | \"odd\" | <processor-list>\n"
          "      <processor-list> ::= <processor>[,<processor>]*\n"
          "      <processor> ::= 0 .. %zu\n"
          "      Optional.\n\n",
          _M_nprocessors - 1);

  fprintf(stderr,
          "    --events-directory <directory>\n"
          "      <directory>: directory where to save the event files.\n"
          "      Default: \"%s\".\n"
          "      Optional.\n\n",
          worker::default_directory);

  fprintf(stderr,
          "    --file-allocation-size <size>\n"
          "      <size>: file allocation size.\n"
          "      Default: %" PRIu64 ".\n"
          "      Optional.\n\n",
          fs::file::default_allocation_size);

  fprintf(stderr,
          "    --event-writer-buffer-size <size>\n"
          "      <size>: size of the event writer buffer.\n"
          "      Greater or equal than: %zu, default: %zu.\n"
          "      Optional.\n",
          event::writer::min_buffer_size,
          event::writer::default_buffer_size);

  fprintf(stderr, "\n");

  fprintf(stderr, "<number> ::= <digit>+\n");
  fprintf(stderr, "<size> ::= <number>[KMG]\n");
  fprintf(stderr, "           Optional suffixes: K (KiB), M (MiB), G (GiB)\n");

  fprintf(stderr, "\n");
}

bool net::mon::configuration::get_number_processors(size_t& nprocessors)
{
  // Get the number of processors currently online.
  long n;
  switch (n = sysconf(_SC_NPROCESSORS_ONLN)) {
    default:
      nprocessors = static_cast<size_t>(n);
      return true;
    case -1:
      fprintf(stderr,
              "Error getting the number of processors currently online.\n");

      return false;
    case 0:
      fprintf(stderr, "No processors currently online.\n");
      return false;
  }
}

bool net::mon::configuration::parse_number_list(const char* s,
                                                size_t min,
                                                size_t max,
                                                size_t minval,
                                                size_t maxval,
                                                size_t& count,
                                                size_t* numbers)
{
  size_t cnt = 0;

  do {
    const char* sep;
    size_t len;
    if ((sep = strchr(s, ',')) != nullptr) {
      len = sep - s;
    } else {
      len = strlen(s);
    }

    uint64_t n;
    if (util::parser::number::parse_view(s, len, n, minval, maxval)) {
      numbers[cnt++] = static_cast<size_t>(n);

      // If the end of the string has not been reached...
      if (sep) {
        s = sep + 1;
      } else {
        if (cnt >= min) {
          count = cnt;
          return true;
        } else {
          return false;
        }
      }
    } else {
      return false;
    }
  } while (cnt < max);

  return false;
}
