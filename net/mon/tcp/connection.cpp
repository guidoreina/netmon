#include "net/mon/tcp/connection.h"

bool net::mon::tcp::connection::process_packet(direction dir,
                                               uint8_t flags,
                                               uint16_t size,
                                               uint64_t now)
{
  // http://cradpdf.drdc-rddc.gc.ca/PDFS/unc25/p520460.pdf

  switch (s) {
    case state::listen:
      if ((flags & flag_mask) == syn) {
        init(dir, size, now);

        return true;
      }

      break;
    case state::connection_requested:
      switch (flags & flag_mask) {
        case syn | ack:
          if (static_cast<originator>(dir) != active_opener) {
            s = state::connection_established;

            sent[static_cast<size_t>(dir)] += size;
            timestamp.last_packet = now;

            return true;
          }

          break;
        case syn:
        case ack:
          // Retransmission / out-of-order?
          if (static_cast<originator>(dir) == active_opener) {
            return true;
          }

          break;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
      }

      break;
    case state::connection_established:
      switch (flags & flag_mask) {
        case ack:
          if (static_cast<originator>(dir) == active_opener) {
            s = state::data_transfer;

            sent[static_cast<size_t>(dir)] += size;
            timestamp.last_packet = now;

            return true;
          }

          break;
        case syn:
          // Retransmission / out-of-order?
          if (static_cast<originator>(dir) == active_opener) {
            return true;
          }

          break;
        case syn | ack:
          // Retransmission / out-of-order?
          if (static_cast<originator>(dir) != active_opener) {
            return true;
          }

          break;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
      }

      break;
    case state::data_transfer:
      switch (flags & flag_mask) {
        case ack:
          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
        case fin:
        case fin | ack:
          s = state::closing;

          active_closer = static_cast<originator>(dir);

          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
        case rst:
        case rst | ack:
          s = state::closed;

          active_closer = static_cast<originator>(dir);

          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
      }

      break;
    case state::closing:
      switch (flags & flag_mask) {
        case ack:
          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
        case fin:
        case fin | ack:
          if (static_cast<originator>(dir) != active_closer) {
            s = state::closed;

            sent[static_cast<size_t>(dir)] += size;
            timestamp.last_packet = now;
          }

          return true;
        case rst:
        case rst | ack:
          s = state::closed;

          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
      }

      break;
    case state::closed:
      switch (flags & flag_mask) {
        case ack:
        case fin:
        case fin | ack:
        case rst:
        case rst | ack:
          sent[static_cast<size_t>(dir)] += size;
          timestamp.last_packet = now;

          return true;
      }

      break;
    case state::failure:
      return false;
  }

  s = state::failure;

  return false;
}
