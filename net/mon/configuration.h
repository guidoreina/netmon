#ifndef NET_MON_CONFIGURATION_H
#define NET_MON_CONFIGURATION_H

#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "net/capture/ring_buffer.h"
#include "net/mon/workers.h"
#include "fs/file.h"

namespace net {
  namespace mon {
    // Network monitor configuration.
    class configuration {
      public:
        // Capture configuration.
        class capture {
          public:
            // Ring buffer configuration.
            class ring_buffer {
              public:
                // Constructor.
                ring_buffer() = default;

                // Destructor.
                ~ring_buffer() = default;

                // Valid configuration?
                bool valid() const;

                // Print configuration.
                void print() const;

                // Show help.
                static void help();

                // Block size.
                size_t block_size =
                       net::capture::ring_buffer::default_block_size;

                // Frame size.
                size_t frame_size =
                       net::capture::ring_buffer::default_frame_size;

                // Frame count.
                size_t frame_count = net::capture::ring_buffer::default_frames;
            };

            // Constructor.
            capture() = default;

            // Destructor.
            ~capture() = default;

            // Valid configuration?
            bool valid() const;

            // Print configuration.
            void print() const;

            // Show help.
            static void help();

            // Capture method.
            enum class method {
              none,
              pcap,
              ring_buffer,
              socket
            };

            method m = method::none;

            // Name of the capture device (either a PCAP filename or the
            // name of a network interface).
            const char* device = nullptr;

            // Index of the network interface.
            unsigned ifindex = 0;

            // Size of the socket receive buffer.
            int rcvbuf_size = 0;

            // Enable promiscuous mode?
            bool promiscuous_mode = false;

            // Ring buffer configuration.
            ring_buffer rb;
        };

        // TCP configuration.
        template<typename Connection>
        class tcp {
          public:
            // Constructor.
            tcp() = default;

            // Destructor.
            ~tcp() = default;

            // Valid configuration?
            bool valid() const;

            // Print configuration.
            void print() const;

            // Show help.
            static void help();

            // Type of the connections class.
            typedef net::mon::tcp::connections<ipv4::tcp::connection>
                    connections_type;

            // Hash table size.
            size_t size = connections_type::default_size;

            // Maximum number of connections.
            size_t maxconns = connections_type::default_max_connections;

            // Connection timeout (seconds).
            uint64_t timeout = connections_type::default_timeout;

            // TCP time wait (seconds).
            uint64_t time_wait = connections_type::default_time_wait;
        };

        // Constructor.
        configuration() = default;

        // Destructor.
        ~configuration() = default;

        // Initialize.
        bool init();

        // Parse configuration.
        bool parse(size_t argc, const char** argv);

        // Valid configuration?
        bool valid() const;

        // Print configuration.
        void print() const;

        // Show help.
        void help(const char* program);

        // Number of workers.
        size_t nworkers = 0;

        // Processor indexes.
        size_t processors[workers::max_workers];

        // Events directory.
        char evdir[PATH_MAX];

        static_assert(strlen(worker::default_directory) < sizeof(evdir),
                      "Name of the events directory is too long.");

        // File allocation size.
        uint64_t file_allocation_size = fs::file::default_allocation_size;

        // Buffer size of the event writer.
        size_t buffer_size = event::writer::default_buffer_size;

        // Capture configuration.
        capture cap;

        // TCP/IPv4 configuration.
        typedef tcp<ipv4::tcp::connection> tcp4_type;
        tcp4_type tcp4;

        // TCP/IPv6 configuration.
        typedef tcp<ipv6::tcp::connection> tcp6_type;
        tcp6_type tcp6;

      private:
        // Number of processors currently online.
        size_t _M_nprocessors;

        // Events directory.
        const char* _M_evdir = nullptr;

        // Get the number of processors currently online.
        static bool get_number_processors(size_t& nprocessors);

        // Parse number list.
        static bool parse_number_list(const char* s,
                                      size_t min,
                                      size_t max,
                                      size_t minval,
                                      size_t maxval,
                                      size_t& count,
                                      size_t* numbers);
    };

    inline bool configuration::init()
    {
      // Get the number of processors currently online.
      if (get_number_processors(_M_nprocessors)) {
        // Initialize processors.
        for (size_t i = 0; i < workers::max_workers; i++) {
          processors[i] = worker::no_processor;
        }

        return true;
      }

      return false;
    }
  }
}

#endif // NET_MON_CONFIGURATION_H
