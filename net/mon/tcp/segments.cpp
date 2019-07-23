#include <string.h>
#include "net/mon/tcp/segments.h"

bool net::mon::tcp::segments::create(payloadfn_t payloadfn,
                                     gapfn_t gapfn,
                                     void* user)
{
  if ((_M_payloads = static_cast<uint8_t*>(
                       malloc(max_segments * max_size)
                     )) != nullptr) {
    uint8_t* payload = _M_payloads;

    for (size_t i = 0; i < max_segments - 1; i++, payload += max_size) {
      _M_segments[i].payload = payload;
      _M_segments[i].next = i + 1;
    }

    _M_segments[max_segments - 1].payload = payload;
    _M_segments[max_segments - 1].next = -1;

    _M_payloadfn = payloadfn;
    _M_gapfn = gapfn;
    _M_user = user;

    return true;
  }

  return false;
}

bool net::mon::tcp::segments::add(uint32_t seqno,
                                  const void* payload,
                                  size_t len)
{
  // If the payload is not too big...
  if (len <= max_size) {
    do {
      // If it is the next sequence number...
      if (seqno == _M_next_seqno) {
        // Notify payload.
        _M_payloadfn(payload, len, _M_user);

        // Increment next sequence number.
        _M_next_seqno = static_cast<uint32_t>(_M_next_seqno + len);

        // Check payloads.
        check_payloads();

        return true;
      } else if (static_cast<uint32_t>(_M_next_seqno - seqno) < 0x80000000u) {
        // Old segment.
        return false;
      }

      // If there are already segments...
      if (_M_last_segment != -1) {
        segment* cur;

        // Start from the end.
        ssize_t i = _M_last_segment;

        // If the sequence number hasn't wrapped around...
        if (seqno >= _M_next_seqno) {
          do {
            cur = &_M_segments[i];

            // If the sequence number is greater or equal...
            if (seqno >= cur->seqno) {
              break;
            }
          } while ((i = cur->prev) != -1);
        } else {
          cur = &_M_segments[i];
        }

        // If it is not the first segment...
        if (i != -1) {
          // If the segments don't overlap...
          if (static_cast<uint32_t>(cur->seqno + cur->len) <= seqno) {
            // If there are free segments...
            if (_M_free_segment != -1) {
              // Save position.
              ssize_t pos = _M_free_segment;

              // Get first free segment.
              segment* s = &_M_segments[pos];

              // If it is the last segment...
              if (cur->next == -1) {
                _M_last_segment = pos;
              } else {
                segment* next = &_M_segments[cur->next];

                // If the segments don't overlap...
                if (static_cast<uint32_t>(seqno + len) <= next->seqno) {
                  next->prev = pos;
                } else {
                  // Invalid sequence number / length.
                  return false;
                }
              }

              _M_free_segment = s->next;

              s->seqno = seqno;

              memcpy(s->payload, payload, len);
              s->len = len;

              s->prev = i;
              s->next = cur->next;

              cur->next = pos;
            } else {
              segment* first = &_M_segments[_M_first_segment];

              // Notify gap.
              _M_gapfn(static_cast<uint32_t>(first->seqno - _M_next_seqno),
                       _M_user);

              _M_next_seqno = first->seqno;

              // Check payloads.
              check_payloads();

              continue;
            }
          } else if ((seqno == cur->seqno) && (len == cur->len)) {
            // Duplicated TCP segment.
            return true;
          } else {
            // Invalid sequence number / length.
            return false;
          }
        } else {
          // If the segments don't overlap...
          if (static_cast<uint32_t>(seqno + len) <= cur->seqno) {
            // If there are free segments...
            if (_M_free_segment != -1) {
              // Save position.
              ssize_t pos = _M_free_segment;

              // Get first free segment.
              segment* s = &_M_segments[pos];

              _M_free_segment = s->next;

              s->seqno = seqno;

              memcpy(s->payload, payload, len);
              s->len = len;

              s->prev = -1;
              s->next = _M_first_segment;

              _M_first_segment = pos;

              cur->prev = pos;
            } else {
              // Notify gap.
              _M_gapfn(static_cast<uint32_t>(seqno - _M_next_seqno), _M_user);

              // Notify payload.
              _M_payloadfn(payload, len, _M_user);

              _M_next_seqno = static_cast<uint32_t>(seqno + len);

              // Check payloads.
              check_payloads();
            }
          } else {
            // Invalid sequence number / length.
            return false;
          }
        }
      } else {
        // Get first free segment.
        segment* s = &_M_segments[_M_free_segment];

        _M_first_segment = _M_free_segment;
        _M_last_segment = _M_free_segment;
        _M_free_segment = s->next;

        s->seqno = seqno;

        memcpy(s->payload, payload, len);
        s->len = len;

        s->prev = -1;
        s->next = -1;
      }

      return true;
    } while (true);
  }

  return false;
}

void net::mon::tcp::segments::fin()
{
  if (_M_first_segment != -1) {
    do {
      // Save position.
      ssize_t pos = _M_first_segment;

      segment* first = &_M_segments[pos];

      _M_first_segment = first->next;

      first->next = _M_free_segment;
      _M_free_segment = pos;

      // If it is the next sequence number...
      if (first->seqno == _M_next_seqno) {
        // Notify payload.
        _M_payloadfn(first->payload, first->len, _M_user);

        // Increment next sequence number.
        _M_next_seqno = static_cast<uint32_t>(_M_next_seqno + first->len);
      }

      // If it is not the last segment...
      if (_M_first_segment != -1) {
        _M_segments[_M_first_segment].prev = -1;
      } else {
        _M_last_segment = -1;
        return;
      }
    } while (true);
  }
}

void net::mon::tcp::segments::check_payloads()
{
  if (_M_first_segment != -1) {
    while (_M_segments[_M_first_segment].seqno <= _M_next_seqno) {
      // Save position.
      ssize_t pos = _M_first_segment;

      segment* first = &_M_segments[pos];

      _M_first_segment = first->next;

      first->next = _M_free_segment;
      _M_free_segment = pos;

      // If it is the next sequence number...
      if (first->seqno == _M_next_seqno) {
        // Notify payload.
        _M_payloadfn(first->payload, first->len, _M_user);

        // Increment next sequence number.
        _M_next_seqno = static_cast<uint32_t>(_M_next_seqno + first->len);
      }

      // If it is not the last segment...
      if (_M_first_segment != -1) {
        _M_segments[_M_first_segment].prev = -1;
      } else {
        _M_last_segment = -1;
        return;
      }
    }
  }
}
