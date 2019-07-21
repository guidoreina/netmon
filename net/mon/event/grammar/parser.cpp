#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <memory>
#include "net/mon/event/grammar/parser.h"
#include "util/parser/number.h"

net::mon::event::grammar::conditional_expression*
net::mon::event::grammar::parser::parse(const char* s)
{
  // Expression stack.
  memory::unique_ptr<conditional_expression> expressions[max_depth];

  // Depth.
  size_t depth = 0;

  // Identifier.
  identifier id;

  // Constant number.
  uint64_t cnumber = 0;

  // Constant string.
  const char* cstr = nullptr;
  size_t cstrlen = 0;

  const char* ptr = s;
  const char* begin = nullptr;

  uint8_t opchar = 0;
  relational_operator op = relational_operator::equal_to;

  uint8_t logical_operators[max_depth];
  logical_operators[0] = 0;

  int state = 0; // Initial state.

  uint8_t c;
  while ((c = *ptr) != 0) {
    switch (state) {
      case 0: // Initial state.
        switch (c) {
          default:
            if ((isalpha(c)) || (c == '_')) {
              begin = ptr;

              state = 1; // Parsing identifier.
            } else {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) while waiting for "
                      "identifier or '(' (offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
            }

            break;
          case '(':
            // If the maximum depth has not been reached...
            if (depth + 1 < max_depth) {
              logical_operators[++depth] = 0;
            } else {
              fprintf(stderr,
                      "Maximum depth (%zu) reached (offset: %zu).\n",
                      max_depth,
                      ptr - s);

              return nullptr;
            }

            break;
          case ' ':
          case '\t':
            break;
        }

        break;
      case 1: // Parsing identifier.
        switch (c) {
          default:
            if ((!isalnum(c)) && (c != '_')) {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) while parsing "
                      "identifier (offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
            }

            break;
          case '=':
          case '!':
          case '<':
          case '>':
          case ' ':
          case '\t':
            state = 2; // Find identifier.
            continue;
        }

        break;
      case 2: // Find identifier.
        {
          size_t len = ptr - begin;
          if (grammar::from_string(begin, len, id)) {
            state = 3; // Before relational operator.
          } else {
            fprintf(stderr,
                    "Unknown identifier '%.*s' (offset: %zu).\n",
                    static_cast<int>(len),
                    begin,
                    ptr - s);

            return nullptr;
          }
        }

        // Fall through.
      case 3: // Before relational operator.
        switch (c) {
          case '=':
          case '!':
          case '<':
          case '>':
            opchar = c;

            state = 4; // Parsing relational operator.
            break;
          case ' ':
          case '\t':
            break;
          default:
            fprintf(stderr,
                    "Invalid character '%c' (0x%02x) while waiting for "
                    "relational operator (offset: %zu).\n",
                    c,
                    c,
                    ptr - s);

            return nullptr;
        }

        break;
      case 4: // Parsing relational operator.
        // Reset constant string.
        cstr = nullptr;

        switch (c) {
          case '=':
            switch (opchar) {
              case '=':
                op = relational_operator::equal_to;
                break;
              case '!':
                op = relational_operator::not_equal_to;
                break;
              case '<':
                op = relational_operator::less_or_equal;
                break;
              case '>':
                op = relational_operator::greater_or_equal;
                break;
            }

            state = 6; // Waiting for constant.
            break;
          case ' ':
          case '\t':
            state = 5; // After relational operator.
            break;
          case '"':
            state = 5; // After relational operator.
            continue;
          default:
            if (isdigit(c)) {
              state = 5; // After relational operator.
              continue;
            } else {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) while waiting for "
                      "constant (offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
            }
        }

        break;
      case 5: // After relational operator.
        switch (opchar) {
          case '<':
            op = relational_operator::less;
            break;
          case '>':
            op = relational_operator::greater;
            break;
          default:
            fprintf(stderr,
                    "Invalid operator '%c' (offset: %zu).\n",
                    static_cast<char>(opchar),
                    ptr - s);

            return nullptr;
        }

        state = 6; // Waiting for constant.

        // Fall through.
      case 6: // Waiting for constant.
        switch (c) {
          default:
            if (isdigit(c)) {
              cnumber = c - '0';

              state = 7; // Parsing integer constant.
            } else {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) while waiting for "
                      "constant (offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
            }

            break;
          case '"':
            cstr = ptr + 1;

            state = 8; // Parsing string literal.
            break;
          case ' ':
          case '\t':
            break;
        }

        break;
      case 7: // Parsing integer constant.
        switch (c) {
          default:
            if (isdigit(c)) {
              uint64_t n;
              if ((n = (cnumber * 10) + (c - '0')) >= cnumber) {
                cnumber = n;
              } else {
                fprintf(stderr, "Number overflow (offset: %zu).\n", ptr - s);
                return nullptr;
              }
            } else {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) while parsing "
                      "integer constant (offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
            }

            break;
          case ')':
          case '&':
          case '|':
            state = 9; // Create expression.
            continue;
          case ' ':
          case '\t':
            state = 9; // Create expression.
            break;
        }

        break;
      case 8: // Parsing string literal.
        if (c == '"') {
          cstrlen = ptr - cstr;

          state = 9; // Create expression.

          continue;
        }

        break;
      case 9: // Create expression.
        {
          memory::unique_ptr<conditional_expression> expr;

          // If the constant is a number...
          if (!cstr) {
            expr.reset(create_expression(id, op, cnumber));
          } else {
            expr.reset(create_expression(id, op, cstr, cstrlen));
          }

          if (expr) {
            if (!add(expressions[depth], expr, logical_operators[depth])) {
              return nullptr;
            }
          } else {
            return nullptr;
          }

          switch (c) {
            case '"':
            case ' ':
            case '\t':
              state = 10; // After constant.
              break;
            case ')':
              state = 11; // Process ')'.
              continue;
            case '&':
            case '|':
              opchar = c;

              state = 13; // After '&' or '|'.
              break;
            default:
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x) after constant "
                      "(offset: %zu).\n",
                      c,
                      c,
                      ptr - s);

              return nullptr;
          }
        }

        break;
      case 10: // After constant.
        switch (c) {
          case ')':
            state = 11; // Process ')'.
            continue;
          case '&':
          case '|':
            opchar = c;

            state = 13; // After '&' or '|'.
            break;
          case ' ':
          case '\t':
            break;
          default:
            fprintf(stderr,
                    "Invalid character '%c' (0x%02x) after constant "
                    "(offset: %zu).\n",
                    c,
                    c,
                    ptr - s);

            return nullptr;
        }

        break;
      case 11: // Process ')'.
        if (depth > 0) {
          // If there is an expression at the current depth...
          if (expressions[depth]) {
            // Add current expression to the previous expression.
            if (add(expressions[depth - 1],
                    expressions[depth],
                    logical_operators[depth - 1])) {
              depth--;

              state = 12; // After ')'.
            } else {
              return nullptr;
            }
          } else {
            fprintf(stderr,
                    "Empty expression (depth: %zu, offset: %zu).\n",
                    depth,
                    ptr - s);

            return nullptr;
          }
        } else {
          fprintf(stderr, "Found ')' at depth 0 (offset: %zu).\n", ptr - s);
          return nullptr;
        }

        break;
      case 12: // After ')'.
        switch (c) {
          case ')':
            state = 11; // Process ')'.
            continue;
          case '&':
          case '|':
            opchar = c;

            state = 13; // After '&' or '|'.
            break;
          case ' ':
          case '\t':
            break;
          default:
            fprintf(stderr,
                    "Invalid character '%c' (0x%02x) after ')' (offset: %zu)."
                    "\n",
                    c,
                    c,
                    ptr - s);

            return nullptr;
        }

        break;
      case 13: // After '&' or '|'.
        switch (c) {
          case '&':
          case '|':
            if (c == opchar) {
              if ((!logical_operators[depth]) ||
                  (logical_operators[depth] == c)) {
                logical_operators[depth] = c;

                state = 0; // Initial state.
              } else {
                fprintf(stderr,
                        "Suggest parentheses around '&&' within '||' "
                        "(offset: %zu).\n",
                        ptr - s);

                return nullptr;
              }
            } else {
              fprintf(stderr,
                      "Invalid character '%c' (0x%02x), '%c' expected "
                      "(offset: %zu).\n",
                      c,
                      c,
                      static_cast<char>(opchar),
                      ptr - s);

              return nullptr;
            }

            break;
          default:
            fprintf(stderr,
                    "Invalid character '%c' (0x%02x), '%c' expected "
                    "(offset: %zu).\n",
                    c,
                    c,
                    static_cast<char>(opchar),
                    ptr - s);

            return nullptr;
        }

        break;
    }

    ptr++;
  }

  if (depth == 0) {
    switch (state) {
      case 7: // Parsing integer constant.
        {
          memory::unique_ptr<conditional_expression>
            expr(create_expression(id, op, cnumber));

          if (expr) {
            if (add(expressions[0], expr, logical_operators[0])) {
              return expressions[0].release();
            }
          }
        }

        break;
      case 10: // After constant.
      case 12: // After ')'.
        return expressions[0].release();
    }
  } else {
    fprintf(stderr, "%zu ')' still need to be closed.\n", depth);
  }

  return nullptr;
}

net::mon::event::grammar::event_expression*
net::mon::event::grammar::parser::create_expression(identifier id,
                                                    relational_operator op,
                                                    uint64_t n)
{
  event_expression* expr = nullptr;

  switch (id) {
    case identifier::source_port:
    case identifier::destination_port:
    case identifier::port:
      if ((n < 1) || (n > 65535)) {
        fprintf(stderr, "Invalid port %" PRIu64 ".\n", n);
        return nullptr;
      }

      break;
    case identifier::icmp_type:
      if (n > 255) {
        fprintf(stderr, "Invalid ICMP type %" PRIu64 ".\n", n);
        return nullptr;
      }

      break;
    case identifier::icmp_code:
      if (n > 255) {
        fprintf(stderr, "Invalid ICMP code %" PRIu64 ".\n", n);
        return nullptr;
      }

      break;
    case identifier::transferred:
    case identifier::number_dns_responses:
    case identifier::payload:
    case identifier::transferred_client:
    case identifier::transferred_server:
      break;
    case identifier::duration:
      // Convert to microseconds.
      n *= 1000000;
      break;
    case identifier::query_type:
      if (n > 65535) {
        fprintf(stderr, "Invalid query type %" PRIu64 ".\n", n);
        return nullptr;
      }

      break;
    default:
      fprintf(stderr,
              "Expected string constant for identifier '%s'.\n",
              to_string(id));

      return nullptr;
  }

  switch (op) {
    case relational_operator::equal_to:
    case relational_operator::not_equal_to:
      expr = new (std::nothrow)
                 equality_expression(static_cast<equality_expression::
                                                 equality_operator>(op));

      break;
    case relational_operator::less:
    case relational_operator::greater:
    case relational_operator::less_or_equal:
    case relational_operator::greater_or_equal:
      expr = new (std::nothrow)
                 relational_expression(static_cast<relational_expression::
                                                   relational_operator>(op));

      break;
  }

  if (expr) {
    expr->init(id, n);
    return expr;
  } else {
    fprintf(stderr, "Error allocating memory.\n");
    return nullptr;
  }
}

net::mon::event::grammar::event_expression*
net::mon::event::grammar::parser::create_expression(identifier id,
                                                    relational_operator op,
                                                    const char* s,
                                                    size_t len)
{
  switch (op) {
    case relational_operator::equal_to:
    case relational_operator::not_equal_to:
      switch (id) {
        case identifier::date:
        case identifier::creation:
          {
            uint64_t timestamp;
            if (parse_timestamp(s, len, timestamp)) {
              event_expression* expr;
              if ((expr = new (std::nothrow)
                          equality_expression(static_cast<equality_expression::
                                              equality_operator>(op))) !=
                  nullptr) {
                expr->init(id, timestamp);

                return expr;
              } else {
                fprintf(stderr, "Error allocating memory.\n");
              }
            } else {
              fprintf(stderr,
                      "Invalid timestamp '%.*s'.\n",
                      static_cast<int>(len),
                      s);
            }
          }

          break;
        case identifier::event_type:
          {
            event::type t;
            if (from_string(s, len, t)) {
              event_expression* expr;
              if ((expr = new (std::nothrow)
                          equality_expression(static_cast<equality_expression::
                                              equality_operator>(op))) !=
                  nullptr) {
                expr->init(id, static_cast<uint64_t>(t));

                return expr;
              } else {
                fprintf(stderr, "Error allocating memory.\n");
              }
            } else {
              fprintf(stderr,
                      "Unknown event type '%.*s'.\n",
                      static_cast<int>(len),
                      s);
            }
          }

          break;
        case identifier::source_ip:
        case identifier::destination_ip:
        case identifier::ip:
          {
            char str[128];
            if (len < sizeof(str)) {
              memcpy(str, s, len);
              str[len] = 0;

              mask netmask;
              if (netmask.build(str)) {
                event_expression* expr;
                if ((expr = new (std::nothrow)
                            equality_expression(
                              static_cast<equality_expression::
                              equality_operator>(op)
                            )) != nullptr) {
                  expr->init(id, netmask);

                  return expr;
                } else {
                  fprintf(stderr, "Error allocating memory.\n");
                }
              } else {
                fprintf(stderr, "Invalid network mask '%s'.\n", str);
              }
            } else {
              fprintf(stderr,
                      "Network mask '%.*s' is too long.\n",
                      static_cast<int>(len),
                      s);
            }
          }

          break;
        case identifier::source_hostname:
        case identifier::destination_hostname:
        case identifier::hostname:
        case identifier::domain:
        case identifier::dns_response:
          if (len <= event_expression::string_max_len) {
            event_expression* expr;
            if ((expr = new (std::nothrow)
                        equality_expression(static_cast<equality_expression::
                                            equality_operator>(op))) !=
                nullptr) {
              expr->init(id, s, len);

              return expr;
            } else {
              fprintf(stderr, "Error allocating memory.\n");
            }
          } else {
            fprintf(stderr,
                    "Constant '%.*s' is too long (%zu characters, "
                    "maximum: %zu characters).\n",
                    static_cast<int>(len),
                    s,
                    len,
                    event_expression::string_max_len);
          }

          break;
        default:
          fprintf(stderr,
                  "Expected numeric constant for identifier '%s'.\n",
                  to_string(id));
      }

      break;
    case relational_operator::less:
    case relational_operator::greater:
    case relational_operator::less_or_equal:
    case relational_operator::greater_or_equal:
      switch (id) {
        case identifier::date:
        case identifier::creation:
          {
            uint64_t timestamp;
            if (parse_timestamp(s, len, timestamp)) {
              event_expression* expr;
              if ((expr = new (std::nothrow)
                          relational_expression(
                            static_cast<relational_expression::
                            relational_operator>(op)
                          )) != nullptr) {
                expr->init(id, timestamp);

                return expr;
              } else {
                fprintf(stderr, "Error allocating memory.\n");
              }
            } else {
              fprintf(stderr,
                      "Invalid timestamp '%.*s'.\n",
                      static_cast<int>(len),
                      s);
            }
          }

          break;
        default:
          fprintf(stderr,
                  "Invalid relational operator for identifier '%s'.\n",
                  to_string(id));
      }
  }

  return nullptr;
}

bool net::mon::event::grammar::
parser::add(memory::unique_ptr<conditional_expression>& dest,
            memory::unique_ptr<conditional_expression>& src,
            uint8_t logical_operator)
{
  if (!dest) {
    dest = src.release();
  } else {
    conditional_expression* cond;

    if (logical_operator == '&') {
      cond = new (std::nothrow) logical_and_expression(dest.get(), src.get());
    } else {
      cond = new (std::nothrow) logical_or_expression(dest.get(), src.get());
    }

    if (cond) {
      dest.release();
      src.release();

      dest = cond;
    } else {
      fprintf(stderr, "Error allocating memory.\n");
      return false;
    }
  }

  return true;
}

bool net::mon::event::grammar::parser::from_string(const char* s,
                                                   size_t len,
                                                   event::type& t)
{
  switch (len) {
    case 4:
      if (strncasecmp(s, "icmp", len) == 0) {
        t = type::icmp;
        return true;
      }

      break;
    case 3:
      if (strncasecmp(s, "udp", len) == 0) {
        t = type::udp;
        return true;
      } else if (strncasecmp(s, "dns", len) == 0) {
        t = type::dns;
        return true;
      }

      break;
    case 9:
      if (strncasecmp(s, "tcp-begin", len) == 0) {
        t = type::tcp_begin;
        return true;
      }

      break;
    case 8:
      if (strncasecmp(s, "tcp-data", len) == 0) {
        t = type::tcp_data;
        return true;
      }

      break;
    case 7:
      if (strncasecmp(s, "tcp-end", len) == 0) {
        t = type::tcp_end;
        return true;
      }
  }

  return false;
}

bool net::mon::event::grammar::parser::parse_timestamp(const char* s,
                                                       size_t len,
                                                       uint64_t& timestamp)
{
  // Format: YYYY/MM/DD hh:mm:ss[.uuuuuu]

  if ((len >= 19) &&
      (len <= 26) &&
      (s[4] == '/') &&
      (s[7] == '/') &&
      (s[10] == ' ') &&
      (s[13] == ':') &&
      (s[16] == ':') &&
      ((len == 19) || (s[19] == '.'))) {
    using namespace util::parser;

    uint64_t year;
    if (number::parse_view(s, 4, year, 2000)) {
      uint64_t mon;
      if (number::parse_view(s + 5, 2, mon, 1, 12)) {
        uint64_t mday;
        if (number::parse_view(s + 8, 2, mday, 1, 31)) {
          uint64_t hour;
          if (number::parse_view(s + 11, 2, hour, 0, 23)) {
            uint64_t min;
            if (number::parse_view(s + 14, 2, min, 0, 59)) {
              uint64_t sec;
              if (number::parse_view(s + 17, 2, sec, 0, 59)) {
                uint64_t usec;

                if (len <= 20) {
                  usec = 0;
                } else {
                  size_t l = len - 20;
                  if (number::parse_view(s + 20, l, usec)) {
                    for (; l < 6; l++) {
                      usec *= 10;
                    }
                  } else {
                    return false;
                  }
                }

                struct tm tm;
                tm.tm_year = static_cast<int>(year) - 1900;
                tm.tm_mon = static_cast<int>(mon) - 1;
                tm.tm_mday = static_cast<int>(mday);
                tm.tm_hour = static_cast<int>(hour);
                tm.tm_min = static_cast<int>(min);
                tm.tm_sec = static_cast<int>(sec);
                tm.tm_isdst = -1;

                timestamp = (mktime(&tm) * 1000000ull) + usec;

                return true;
              }
            }
          }
        }
      }
    }
  }

  return false;
}
