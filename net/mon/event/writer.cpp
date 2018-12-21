#include "net/mon/event/writer.h"

bool net::mon::event::writer::open(const char* filename)
{
  // Open file.
  if (_M_file.open(filename)) {
    uint8_t header[file::header::size];

    // If the file is not empty...
    if (!_M_file.empty()) {
      // Read header.
      if (_M_file.pread(header, sizeof(header), 0) ==
          static_cast<ssize_t>(sizeof(header))) {
        // Deserialize header.
        if (_M_header.deserialize(header, sizeof(header))) {
          return true;
        }
      }
    } else {
      // File is empty.

      // Initialize header.
      _M_header.timestamp.first = 0;
      _M_header.timestamp.last = 0;

      // Serialize header.
      _M_header.serialize(header, sizeof(header));

      // Write header at the beginning of the file.
      if (_M_file.pwrite(header, sizeof(header), 0)) {
        return true;
      }
    }

    _M_file.close();
  }

  return false;
}

bool net::mon::event::writer::close()
{
  // If the file is open...
  if (_M_file.open()) {
    // Flush remaining data (if any).
    if (flush()) {
      // Serialize header.
      uint8_t header[file::header::size];
      _M_header.serialize(header, sizeof(header));

      // Write header at the beginning of the file.
      bool ret = _M_file.pwrite(header, sizeof(header), 0);

      _M_file.close();

      return ret;
    } else {
      _M_file.close();

      return false;
    }
  } else {
    return true;
  }
}
