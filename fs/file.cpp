#include <errno.h>
#include "fs/file.h"

ssize_t fs::file::pread(void* buf, size_t count, uint64_t off)
{
  uint64_t end;
  if ((end = off + count) >= off) {
    // If the offset is not beyond the end of the file...
    if (off < _M_used) {
      if (end > _M_used) {
        count = _M_used - off;
      }

      uint8_t* b = static_cast<uint8_t*>(buf);
      size_t read = 0;

      do {
        ssize_t ret;
        switch (ret = ::pread(_M_fd, b, count, off)) {
          default:
            read += ret;

            if ((count -= ret) == 0) {
              return read;
            }

            b += ret;
            off += ret;

            break;
          case 0:
            return read;
          case -1:
            if (errno != EINTR) {
              return (read > 0) ? read : -1;
            }

            break;
        }
      } while (true);
    } else if (off == _M_used) {
      return 0;
    }
  }

  return -1;
}

bool fs::file::pwrite(const void* buf, size_t count, uint64_t off)
{
  uint64_t end;
  if ((end = off + count) >= off) {
    // If the file has to be extended...
    if (end > _M_size) {
      uint64_t size = _M_allocation_size;
      uint64_t diff = end - _M_size;

      while (size < diff) {
        uint64_t tmp;
        if ((tmp = size + _M_allocation_size) > size) {
          size = tmp;
        } else {
          // Overflow.
          return false;
        }
      }

      if (!reserve(size)) {
        return false;
      }
    }

    const uint8_t* b = static_cast<const uint8_t*>(buf);

    do {
      ssize_t ret;
      switch (ret = ::pwrite(_M_fd, b, count, off)) {
        default:
          if ((count -= ret) == 0) {
            if (end > _M_used) {
              _M_used = end;
            }

            return true;
          }

          b += ret;
          off += ret;

          break;
        case 0:
          return (count == 0);
        case -1:
          if (errno != EINTR) {
            return false;
          }

          break;
      }
    } while (true);
  }

  return false;
}
