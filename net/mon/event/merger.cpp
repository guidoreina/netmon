#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <memory>
#include "net/mon/event/merger.h"
#include "net/mon/event/reader.h"
#include "fs/file.h"
#include "string/buffer.h"

bool net::mon::event::merger::merge(const char** infiles,
                                    size_t ninfiles,
                                    const char* outfile)
{
  struct stat sbuf;
  if ((ninfiles >= 2) && (stat(outfile, &sbuf) < 0)) {
    reader* readers;
    if ((readers = new (std::nothrow) reader[ninfiles]) != nullptr) {
      // Open input files.
      for (size_t i = 0; i < ninfiles; i++) {
        if (!readers[i].open(infiles[i])) {
          delete [] readers;
          return false;
        }
      }

      // Open output file.
      fs::file output;
      if (output.open(outfile)) {
        struct entry {
          const void* event;
          size_t len;
          uint64_t timestamp;
        };

        entry* entries;
        if ((entries = new (std::nothrow) entry[ninfiles]) != nullptr) {
          file::header header;
          header.timestamp.first = ULLONG_MAX;
          header.timestamp.last = 0;

          // Fill entries with the first event of each input file.
          for (size_t i = 0; i < ninfiles; i++) {
            if (readers[i].next(entries[i].event,
                                entries[i].len,
                                entries[i].timestamp)) {
              if (entries[i].timestamp < header.timestamp.first) {
                header.timestamp.first = entries[i].timestamp;
              }
            } else {
              entries[i].timestamp = ULLONG_MAX;
            }
          }

          string::buffer buf;

          uint64_t off = file::header::size;

          do {
            uint64_t timestamp = ULLONG_MAX;

            // Search event with the oldest timestamp.
            size_t idx = 0;
            for (size_t i = 0; i < ninfiles; i++) {
              if (entries[i].timestamp < timestamp) {
                timestamp = entries[i].timestamp;

                // Save index.
                idx = i;
              }
            }

            // If there are still events...
            if (timestamp != ULLONG_MAX) {
              // Add event to the buffer.
              if (buf.append(static_cast<const char*>(entries[idx].event),
                             entries[idx].len)) {
                header.timestamp.last = timestamp;

                // If the buffer is full...
                if (buf.length() >= max_buffer_size) {
                  // Write buffer to disk.
                  if (output.pwrite(buf.data(), buf.length(), off)) {
                    off += buf.length();

                    buf.clear();
                  } else {
                    output.close();

                    unlink(outfile);

                    delete [] entries;
                    delete [] readers;

                    return false;
                  }
                }

                // Read next event.
                if (!readers[idx].next(entries[idx].event,
                                       entries[idx].len,
                                       entries[idx].timestamp)) {
                  entries[idx].timestamp = ULLONG_MAX;
                }
              } else {
                output.close();

                unlink(outfile);

                delete [] entries;
                delete [] readers;

                return false;
              }
            } else {
              break;
            }
          } while (true);

          delete [] entries;
          delete [] readers;

          // If there are events...
          if (header.timestamp.first != ULLONG_MAX) {
            if ((buf.empty()) ||
                (output.pwrite(buf.data(), buf.length(), off))) {
              // Serialize header.
              uint8_t buf[file::header::size];
              header.serialize(buf, sizeof(buf));

              // Write header at the beginning of the file.
              if (output.pwrite(buf, sizeof(buf), 0)) {
                return true;
              }
            }
          }

          output.close();

          unlink(outfile);

          return (header.timestamp.first == ULLONG_MAX);
        }
      }

      delete [] readers;
    }
  }

  return false;
}
