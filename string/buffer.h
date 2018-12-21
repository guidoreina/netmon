#ifndef STRING_BUFFER_H
#define STRING_BUFFER_H

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

namespace string {
  class buffer {
    public:
      // Constructor.
      buffer();
      buffer(buffer&& other);

      // Destructor.
      ~buffer();

      // Move assignment operator.
      buffer& operator=(buffer&& other);

      // Swap content.
      void swap(buffer& other);

      // Free buffer.
      void free();

      // Clear buffer.
      void clear();

      // Get data.
      const char* data() const;
      char* data();

      // Get end.
      char* end();

      // Get size of allocated storage.
      size_t capacity() const;

      // Empty?
      bool empty() const;

      // Get length.
      size_t length() const;

      // Increment length.
      void increment_length(size_t inc);

      // Get remaining space available.
      size_t remaining() const;

      // Allocate memory.
      bool allocate(size_t size);

      // Append.
      bool append(char c);
      bool append(const char* string);
      bool append(const char* string, size_t len);

      // NULL-terminate string.
      void null_terminate();

      // Format string.
      bool format(const char* format, ...);
      bool vformat(const char* format, va_list ap);

    private:
      static constexpr const size_t initial_size = 32;

      char* _M_data;
      size_t _M_size;
      size_t _M_used;

      // Disable copy constructor and assignment operator.
      buffer(const buffer&) = delete;
      buffer& operator=(const buffer&) = delete;
  };

  inline buffer::buffer()
    : _M_data(nullptr),
      _M_size(0),
      _M_used(0)
  {
  }

  inline buffer::buffer(buffer&& other)
    : _M_data(other._M_data),
      _M_size(other._M_size),
      _M_used(other._M_used)
  {
    other._M_data = nullptr;
    other._M_size = 0;
    other._M_used = 0;
  }

  inline buffer::~buffer()
  {
    free();
  }

  inline buffer& buffer::operator=(buffer&& other)
  {
    _M_data = other._M_data;
    _M_size = other._M_size;
    _M_used = other._M_used;

    other._M_data = nullptr;
    other._M_size = 0;
    other._M_used = 0;

    return *this;
  }

  inline void buffer::swap(buffer& other)
  {
    char* data = _M_data;
    _M_data = other._M_data;
    other._M_data = data;

    size_t s = _M_size;
    _M_size = other._M_size;
    other._M_size = s;

    s = _M_used;
    _M_used = other._M_used;
    other._M_used = s;
  }

  inline void buffer::free()
  {
    if (_M_data) {
      ::free(_M_data);
      _M_data = nullptr;
    }

    _M_size = 0;
    _M_used = 0;
  }

  inline void buffer::clear()
  {
    _M_used = 0;
  }

  inline const char* buffer::data() const
  {
    return _M_data;
  }

  inline char* buffer::data()
  {
    return _M_data;
  }

  inline char* buffer::end()
  {
    return _M_data + _M_used;
  }

  inline size_t buffer::capacity() const
  {
    return _M_size;
  }

  inline bool buffer::empty() const
  {
    return (_M_used == 0);
  }

  inline size_t buffer::length() const
  {
    return _M_used;
  }

  inline void buffer::increment_length(size_t inc)
  {
    _M_used += inc;
  }

  inline size_t buffer::remaining() const
  {
    return _M_size - _M_used;
  }

  inline bool buffer::append(char c)
  {
    if (allocate(1)) {
      _M_data[_M_used++] = c;
      return true;
    }

    return false;
  }

  inline bool buffer::append(const char* string)
  {
    return string ? append(string, strlen(string)) : true;
  }

  inline bool buffer::append(const char* string, size_t len)
  {
    if (len > 0) {
      if (allocate(len)) {
        memcpy(end(), string, len);
        _M_used += len;

        return true;
      }

      return false;
    }

    return true;
  }

  inline void buffer::null_terminate()
  {
    _M_data[_M_used] = 0;
  }

  inline bool buffer::format(const char* format, ...)
  {
    va_list ap;
    va_start(ap, format);

    bool ret = vformat(format, ap);

    va_end(ap);

    return ret;
  }
}

#endif // STRING_BUFFER_H
