#ifndef FS_FILE_H
#define FS_FILE_H

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

namespace fs {
  class file {
    public:
      // Default allocation size.
      static constexpr const uint64_t
             default_allocation_size = 1024ull * 1024ull * 1024ull;

      // Constructor.
      file(uint64_t allocation_size = default_allocation_size);

      // Destructor.
      ~file();

      // Open.
      bool open(const char* filename);

      // Is the file open?
      bool open() const;

      // Close.
      bool close();

      // Read at a given offset.
      ssize_t pread(void* buf, size_t count, uint64_t off);

      // Write.
      bool write(const void* buf, size_t count);

      // Write at a given offset.
      bool pwrite(const void* buf, size_t count, uint64_t off);

      // Get filesize.
      uint64_t size() const;

      // Is the file empty?
      bool empty() const;

    private:
      int _M_fd = -1;

      uint64_t _M_size;
      uint64_t _M_used;

      uint64_t _M_allocation_size;

      // Reserve space in the file.
      bool reserve(uint64_t count);

      // Disable copy constructor and assignment operator.
      file(const file&) = delete;
      file& operator=(const file&) = delete;
  };

  inline file::file(uint64_t allocation_size)
    : _M_allocation_size(allocation_size)
  {
  }

  inline file::~file()
  {
    close();
  }

  inline bool file::open(const char* filename)
  {
    if ((_M_fd = ::open(filename, O_CREAT | O_RDWR, 0644)) != -1) {
      // Get filesize.
      off_t filesize;
      if ((filesize = lseek(_M_fd, 0, SEEK_END)) != -1) {
        // Save filesize.
        _M_size = filesize;
        _M_used = filesize;

        return reserve(_M_allocation_size);
      }
    }

    return false;
  }

  inline bool file::open() const
  {
    return (_M_fd != -1);
  }

  inline bool file::close()
  {
    if (_M_fd != -1) {
      bool ret = (ftruncate(_M_fd, _M_used) == 0);

      ::close(_M_fd);
      _M_fd = -1;

      return ret;
    }

    return true;
  }

  inline bool file::write(const void* buf, size_t count)
  {
    return pwrite(buf, count, _M_used);
  }

  inline uint64_t file::size() const
  {
    return _M_used;
  }

  inline bool file::empty() const
  {
    return (_M_used == 0);
  }

  inline bool file::reserve(uint64_t count)
  {
    uint64_t size;
    if ((size = _M_size + count) >= _M_size) {
      if (ftruncate(_M_fd, size) == 0) {
        _M_size = size;

        return true;
      }
    }

    return false;
  }
}

#endif // FS_FILE_H
