#ifndef NET_MON_EVENT_MERGER_H
#define NET_MON_EVENT_MERGER_H

#include <sys/types.h>

namespace net {
  namespace mon {
    namespace event {
      // Event merger.
      class merger {
        public:
          // Merge events in the input files into the output file.
          static bool merge(const char** infiles,
                            size_t ninfiles,
                            const char* outfile);

        private:
          // Maximum buffer size before writing the events to disk.
          static constexpr const size_t max_buffer_size = 64 * 1024;
      };
    }
  }
}

#endif // NET_MON_EVENT_MERGER_H
