#ifndef NET_MON_EVENT_WRITER_H
#define NET_MON_EVENT_WRITER_H

#include "net/mon/event/events.h"
#include "net/mon/event/file.h"
#include "fs/file.h"

namespace net {
  namespace mon {
    namespace event {
      // Event writer.
      class writer {
        public:
          // Minimum buffer size.
          static constexpr const size_t min_buffer_size = event::maxlen;

          // Default buffer size.
          static constexpr const size_t default_buffer_size = 32 * 1024;

          // Constructor.
          writer(uint64_t file_allocation_size =
                          fs::file::default_allocation_size,
                 size_t buffer_size = default_buffer_size);

          // Destructor.
          ~writer();

          // Initialize.
          bool init();

          // Open event file for writing.
          bool open(const char* filename);

          // Close event file.
          bool close();

          // Write event.
          template<typename Event>
          bool write(const Event& ev);

          // Flush buffer.
          bool flush();

        private:
          fs::file _M_file;

          file::header _M_header;

          string::buffer _M_buf;

          size_t _M_buffer_size;

          // Flush buffer.
          bool flush_();

          // Disable copy constructor and assignment operator.
          writer(const writer&) = delete;
          writer& operator=(const writer&) = delete;
      };

      inline writer::writer(uint64_t file_allocation_size, size_t buffer_size)
        : _M_file(file_allocation_size),
          _M_buffer_size(buffer_size)
      {
      }

      inline writer::~writer()
      {
        close();
      }

      inline bool writer::init()
      {
        return (_M_buf.allocate(_M_buffer_size * 2));
      }

      template<typename Event>
      inline bool writer::write(const Event& ev)
      {
        if ((ev.serialize(_M_buf)) &&
            ((_M_buf.length() < _M_buffer_size) || (flush_()))) {
          if (_M_header.timestamp.first == 0) {
            _M_header.timestamp.first = ev.timestamp;
          }

          _M_header.timestamp.last = ev.timestamp;

          return true;
        }

        return false;
      }

      inline bool writer::flush()
      {
        return !_M_buf.empty() ? flush_() : true;
      }

      inline bool writer::flush_()
      {
        // Write buffer to file.
        if (_M_file.write(_M_buf.data(), _M_buf.length())) {
          _M_buf.clear();

          return true;
        }

        return false;
      }
    }
  }
}

#endif // NET_MON_EVENT_WRITER_H
