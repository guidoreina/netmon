#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "net/mon/workers.h"
#include "net/mon/configuration.h"
#include "net/capture/method.h"
#include "pcap/reader.h"

static bool process_pcap_file(const net::mon::configuration& config);
static bool process_interface(const net::mon::configuration& config);

static bool ethernet(const void* buf,
                     size_t len,
                     const pcap::timeval& ts,
                     void* user);

static bool ipv4(const void* buf,
                 size_t len,
                 const pcap::timeval& ts,
                 void* user);

static bool ipv6(const void* buf,
                 size_t len,
                 const pcap::timeval& ts,
                 void* user);

struct pcap_argument {
  net::mon::worker* worker;
  const pcap::reader* reader;
};

int main(int argc, const char** argv)
{
  // Initialize configuration.
  net::mon::configuration config;
  if (config.init()) {
    // Parse program options.
    if (config.parse(argc, argv)) {
      // Print configuration.
      config.print();

      if (config.cap.m == net::mon::configuration::capture::method::pcap) {
        if (process_pcap_file(config)) {
          return 0;
        }
      } else {
        if (process_interface(config)) {
          return 0;
        }
      }
    } else {
      config.help(argv[0]);
    }
  } else {
    fprintf(stderr, "Error initializing configuration.\n");
  }

  return -1;
}

bool process_pcap_file(const net::mon::configuration& config)
{
  // Open PCAP file.
  pcap::reader reader;
  if (reader.open(config.cap.device)) {
    // Initialize netmon worker.
    net::mon::worker worker(0,
                            net::mon::worker::no_processor,
                            config.evdir,
                            config.file_allocation_size,
                            config.buffer_size);

    if (worker.init("pcap",
                    config.tcp4.size,
                    config.tcp4.maxconns,
                    config.tcp6.size,
                    config.tcp6.maxconns,
                    config.tcp4.timeout,
                    config.tcp4.time_wait)) {
      pcap::callbacks callbacks;
      callbacks.ethernet = ethernet;
      callbacks.ipv4 = ipv4;
      callbacks.ipv6 = ipv6;

      pcap_argument arg;
      arg.worker = &worker;
      arg.reader = &reader;

      // Read PCAP file.
      if (reader.read_all(callbacks, &arg)) {
        // Remove expired connections.
        const pcap::timeval& timestamp = reader.timestamp();

        worker.remove_expired((timestamp.tv_sec * 1000000ull) +
                              timestamp.tv_usec);

        return true;
      }

      fprintf(stderr, "Error adding packet.\n");
    } else {
      fprintf(stderr, "Error initializing netmon worker.\n");
    }
  } else {
    fprintf(stderr,
            "Error opening file '%s' for reading.\n",
            config.cap.device);
  }

  return false;
}

bool process_interface(const net::mon::configuration& config)
{
  net::capture::method capture_method;
  if (config.cap.m == net::mon::configuration::capture::method::ring_buffer) {
    capture_method = net::capture::method::ring_buffer;
  } else {
    capture_method = net::capture::method::socket;
  }

  // Create netmon workers.
  net::mon::workers workers;
  if (workers.create(config.nworkers,
                     config.processors,
                     config.evdir,
                     config.file_allocation_size,
                     config.buffer_size,
                     capture_method,
                     config.cap.device,
                     config.cap.ifindex,
                     config.cap.rcvbuf_size,
                     config.cap.promiscuous_mode,
                     config.cap.rb.block_size,
                     config.cap.rb.frame_size,
                     config.cap.rb.frame_count,
                     config.tcp4.size,
                     config.tcp4.maxconns,
                     config.tcp6.size,
                     config.tcp6.maxconns,
                     config.tcp4.timeout,
                     config.tcp4.time_wait)) {
    // Block signals SIGINT and SIGTERM.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) == 0) {
      // Start workers.
      if (workers.start()) {
        printf("Waiting for signal to arrive.\n");

        // Wait for signal to arrive.
        int sig;
        while (sigwait(&set, &sig) != 0);

        printf("Signal received.\n");

        workers.stop();

        workers.show_statistics();

        return true;
      } else {
        fprintf(stderr, "Error starting workers.\n");
      }
    } else {
      fprintf(stderr, "Error blocking signals SIGINT and SIGTERM.\n");
    }
  } else {
    fprintf(stderr, "Error creating workers.\n");
  }

  return false;
}

bool ethernet(const void* buf, size_t len, const pcap::timeval& ts, void* user)
{
  uint32_t usec = (static_cast<pcap_argument*>(user)->reader->resolution() ==
                   pcap::resolution::microseconds) ? ts.tv_usec :
                                                     ts.tv_usec / 1000;

  // Process ethernet frame.
  return static_cast<pcap_argument*>(user)->worker->process_ethernet(
           buf,
           len,
           {static_cast<time_t>(ts.tv_sec), static_cast<suseconds_t>(usec)}
         );
}

bool ipv4(const void* buf, size_t len, const pcap::timeval& ts, void* user)
{
  uint32_t usec = (static_cast<pcap_argument*>(user)->reader->resolution() ==
                   pcap::resolution::microseconds) ? ts.tv_usec :
                                                     ts.tv_usec / 1000;

  // Process IPv4 packet.
  return static_cast<pcap_argument*>(user)->worker->process_ipv4(
           buf,
           len,
           {static_cast<time_t>(ts.tv_sec), static_cast<suseconds_t>(usec)}
         );
}

bool ipv6(const void* buf, size_t len, const pcap::timeval& ts, void* user)
{
  uint32_t usec = (static_cast<pcap_argument*>(user)->reader->resolution() ==
                   pcap::resolution::microseconds) ? ts.tv_usec :
                                                     ts.tv_usec / 1000;

  // Process IPv6 packet.
  return static_cast<pcap_argument*>(user)->worker->process_ipv6(
           buf,
           len,
           {static_cast<time_t>(ts.tv_sec), static_cast<suseconds_t>(usec)}
         );
}
