#include <stdlib.h>
#include <stdio.h>
#include "string/buffer.h"

bool string::buffer::allocate(size_t size)
{
  // Add space for the null character.
  size_t s;
  if ((s = _M_used + size + 1) > size) {
    if (s <= _M_size) {
      return true;
    }

    size = s;

    if (_M_size > 0) {
      if ((s = _M_size * 2) <= _M_size) {
        // Overflow.
        return false;
      }
    } else {
      s = initial_size;
    }

    while (s < size) {
      size_t tmp;
      if ((tmp = s * 2) > s) {
        s = tmp;
      } else {
        // Overflow.
        return false;
      }
    }

    char* data;
    if ((data = static_cast<char*>(realloc(_M_data, s))) != nullptr) {
      _M_data = data;
      _M_size = s;

      return true;
    }
  }

  return false;
}

bool string::buffer::vformat(const char* format, va_list ap)
{
  if (allocate(initial_size - 1)) {
    size_t size = remaining();

    do {
      va_list aq;
      va_copy(aq, ap);
      int n = vsnprintf(end(), size, format, aq);
      va_end(aq);

      if (n > -1) {
        if (static_cast<size_t>(n) < size) {
          increment_length(n);
          return true;
        }

        size = n + 1;
      } else {
        size *= 2;
      }
    } while (allocate(size));
  }

  return false;
}
