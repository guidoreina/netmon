#ifndef NET_MON_EVENT_GRAMMAR_PARSER_H
#define NET_MON_EVENT_GRAMMAR_PARSER_H

#include "net/mon/event/grammar/expressions.h"
#include "memory/unique_ptr.h"

namespace net {
  namespace mon {
    namespace event {
      namespace grammar {
        // Parser.
        class parser {
          public:
            // Constructor.
            parser() = default;

            // Destructor.
            ~parser() = default;

            // Parse.
            static conditional_expression* parse(const char* s);

          private:
            // Maximum depth.
            static constexpr const size_t max_depth = 64;

            // Create event expression.
            static event_expression* create_expression(identifier id,
                                                       relational_operator op,
                                                       uint64_t n);

            static event_expression* create_expression(identifier id,
                                                       relational_operator op,
                                                       const char* s,
                                                       size_t len);

            // Add expression.
            static bool add(memory::unique_ptr<conditional_expression>& dest,
                            memory::unique_ptr<conditional_expression>& src,
                            uint8_t logical_operator);

            // Get event type from string.
            static bool from_string(const char* s, size_t len, event::type& t);

            // Parse timestamp.
            static bool parse_timestamp(const char* s,
                                        size_t len,
                                        uint64_t& timestamp);

            // Is alphabetic.
            static bool isalpha(uint8_t c);

            // Is digit.
            static bool isdigit(uint8_t c);

            // Is alphanumeric.
            static bool isalnum(uint8_t c);
        };

        inline bool parser::isalpha(uint8_t c)
        {
          return (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')));
        }

        inline bool parser::isdigit(uint8_t c)
        {
          return ((c >= '0') && (c <= '9'));
        }

        inline bool parser::isalnum(uint8_t c)
        {
          return ((isalpha(c)) || (isdigit(c)));
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_GRAMMAR_PARSER_H
