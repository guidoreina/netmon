#ifndef NET_MON_EVENT_GRAMMAR_EXPRESSIONS_H
#define NET_MON_EVENT_GRAMMAR_EXPRESSIONS_H

#include <stdint.h>
#include <string.h>
#include "net/mon/event/events.h"
#include "net/mask.h"

namespace net {
  namespace mon {
    namespace event {
      namespace grammar {
        // Conditional expression.
        class conditional_expression {
          public:
            // Constructor.
            conditional_expression() = default;

            // Destructor.
            virtual ~conditional_expression() = default;

            // Evaluate expression.
            virtual bool evaluate(const icmp& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;

            virtual bool evaluate(const udp& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;

            virtual bool evaluate(const dns& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;

            virtual bool evaluate(const tcp_begin& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;

            virtual bool evaluate(const tcp_data& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;

            virtual bool evaluate(const tcp_end& ev,
                                  const char* srchostname,
                                  const char* desthostname) const = 0;
        };

        // Logical AND expression.
        class logical_and_expression : public conditional_expression {
          public:
            // Constructor.
            logical_and_expression(conditional_expression* left,
                                   conditional_expression* right);

            // Destructor.
            ~logical_and_expression();

            // Evaluate expression.
            bool evaluate(const icmp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const udp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const dns& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_begin& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_data& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_end& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

          private:
            conditional_expression* _M_left;
            conditional_expression* _M_right;

            // Evaluate expression.
            template<typename Event>
            bool evaluate_(const Event& ev,
                           const char* srchostname,
                           const char* desthostname) const;
        };

        // Logical OR expression.
        class logical_or_expression : public conditional_expression {
          public:
            // Constructor.
            logical_or_expression(conditional_expression* left,
                                  conditional_expression* right);

            // Destructor.
            ~logical_or_expression();

            // Evaluate expression.
            bool evaluate(const icmp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const udp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const dns& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_begin& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_data& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_end& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

          private:
            conditional_expression* _M_left;
            conditional_expression* _M_right;

            // Evaluate expression.
            template<typename Event>
            bool evaluate_(const Event& ev,
                           const char* srchostname,
                           const char* desthostname) const;
        };

        // NOT expression.
        class not_expression : public conditional_expression {
          public:
            // Constructor.
            not_expression(conditional_expression* expr);

            // Destructor.
            ~not_expression();

            // Evaluate expression.
            bool evaluate(const icmp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const udp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const dns& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_begin& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_data& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_end& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

          private:
            conditional_expression* _M_expr;

            // Evaluate expression.
            template<typename Event>
            bool evaluate_(const Event& ev,
                           const char* srchostname,
                           const char* desthostname) const;
        };

        // Identifier.
        enum class identifier {
          date,
          event_type,
          source_ip,
          source_hostname,
          source_port,
          destination_ip,
          destination_hostname,
          destination_port,
          ip,
          hostname,
          port,
          icmp_type,
          icmp_code,
          transferred,
          query_type,
          domain,
          number_dns_responses,
          dns_response,
          payload,
          creation,
          duration,
          transferred_client,
          transferred_server
        };

        bool from_string(const char* s, size_t len, identifier& id);
        const char* to_string(identifier id);

        enum class relational_operator : unsigned {
          equal_to,
          not_equal_to,
          less,
          greater,
          less_or_equal,
          greater_or_equal
        };

        // Event expression.
        class event_expression : public conditional_expression {
          public:
            // Maximum length of the constant string.
            static constexpr const size_t string_max_len = 255;

            // Constructor.
            event_expression() = default;

            // Destructor.
            virtual ~event_expression() = default;

            // Initialize.
            void init(identifier id, uint64_t n);
            bool init(identifier id, const char* s, size_t len);
            void init(identifier id, const mask& netmask);

            // Get identifier.
            identifier id() const;

            // Get number.
            uint64_t number() const;

            // Get string.
            const char* string() const;

            // Get string length.
            size_t string_length() const;

            // Get network mask.
            const mask& netmask() const;

          private:
            // Identifier.
            identifier _M_identifier;

            // Number.
            uint64_t _M_number = 0;

            // String.
            char _M_str[string_max_len + 1] = {0};

            // String length.
            size_t _M_strlen = 0;

            // Network mask.
            mask _M_netmask;
        };

        // Equality expression.
        class equality_expression : public event_expression {
          public:
            enum class equality_operator : unsigned {
              equal_to = static_cast<unsigned>(relational_operator::equal_to),
              not_equal_to = static_cast<unsigned>(
                               relational_operator::not_equal_to
                             )
            };

            // Constructor.
            equality_expression(equality_operator op);

            // Destructor.
            ~equality_expression() = default;

            // Evaluate expression.
            bool evaluate(const icmp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const udp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const dns& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_begin& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_data& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_end& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

          private:
            // Equality operator.
            equality_operator _M_operator;

            // Evaluate event type.
            bool evaluate_event_type(event::type type) const;

            // Evaluate source IP.
            template<typename Event>
            bool evaluate_source_ip(const Event& ev) const;

            // Evaluate destination IP.
            template<typename Event>
            bool evaluate_destination_ip(const Event& ev) const;

            // Evaluate IP.
            template<typename Event>
            bool evaluate_ip(const Event& ev) const;

            // Evaluate hostname.
            bool evaluate_hostname(const char* hostname) const;

            // Evaluate hostnames.
            bool evaluate_hostnames(const char* srchostname,
                                    const char* desthostname) const;

            // Evaluate port.
            template<typename Event>
            bool evaluate_port(const Event& ev) const;

            // Evaluate number.
            bool evaluate_number(uint64_t n) const;

            static bool ip_match(const mask& netmask,
                                 const void* addr,
                                 size_t len);

            static bool have_dns_response(const char* ip, const dns& ev);

            // Convert IPv4 and IPv6 addresses from text to binary form.
            static bool ip_text_to_binary(const char* ip,
                                          void* addr,
                                          size_t& addrlen);
        };

        // Relational expression.
        class relational_expression : public event_expression {
          public:
            enum class relational_operator : unsigned {
              less = static_cast<unsigned>(grammar::relational_operator::less),
              greater = static_cast<unsigned>(
                          grammar::relational_operator::greater
                        ),

              less_or_equal = static_cast<unsigned>(
                                grammar::relational_operator::less_or_equal
                              ),

              greater_or_equal =
                static_cast<unsigned>(
                  grammar::relational_operator::greater_or_equal
                )
            };

            // Constructor.
            relational_expression(relational_operator op);

            // Destructor.
            ~relational_expression() = default;

            // Evaluate expression.
            bool evaluate(const icmp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const udp& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const dns& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_begin& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_data& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

            bool evaluate(const tcp_end& ev,
                          const char* srchostname,
                          const char* desthostname) const final;

          private:
            // Relational operator.
            relational_operator _M_operator;

            // Evaluate port.
            template<typename Event>
            bool evaluate_port(const Event& ev) const;

            // Evaluate number.
            bool evaluate_number(uint64_t n) const;
        };


        ////////////////////////////////
        //                            //
        // logical_and_expression     //
        //                            //
        ////////////////////////////////

        inline logical_and_expression::
        logical_and_expression(conditional_expression* left,
                               conditional_expression* right)
          : _M_left(left),
            _M_right(right)
        {
        }

        inline logical_and_expression::~logical_and_expression()
        {
          delete _M_left;
          delete _M_right;
        }

        inline
        bool logical_and_expression::evaluate(const icmp& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_and_expression::evaluate(const udp& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_and_expression::evaluate(const dns& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_and_expression::evaluate(const tcp_begin& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_and_expression::evaluate(const tcp_data& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_and_expression::evaluate(const tcp_end& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        template<typename Event>
        inline
        bool logical_and_expression::evaluate_(const Event& ev,
                                               const char* srchostname,
                                               const char* desthostname) const
        {
          return ((_M_left->evaluate(ev, srchostname, desthostname)) &&
                  (_M_right->evaluate(ev, srchostname, desthostname)));
        }


        ////////////////////////////////
        //                            //
        // logical_or_expression      //
        //                            //
        ////////////////////////////////

        inline logical_or_expression::
        logical_or_expression(conditional_expression* left,
                              conditional_expression* right)
          : _M_left(left),
            _M_right(right)
        {
        }

        inline logical_or_expression::~logical_or_expression()
        {
          delete _M_left;
          delete _M_right;
        }

        inline
        bool logical_or_expression::evaluate(const icmp& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_or_expression::evaluate(const udp& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_or_expression::evaluate(const dns& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_or_expression::evaluate(const tcp_begin& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_or_expression::evaluate(const tcp_data& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool logical_or_expression::evaluate(const tcp_end& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        template<typename Event>
        inline
        bool logical_or_expression::evaluate_(const Event& ev,
                                              const char* srchostname,
                                              const char* desthostname) const
        {
          return ((_M_left->evaluate(ev, srchostname, desthostname)) ||
                  (_M_right->evaluate(ev, srchostname, desthostname)));
        }


        ////////////////////////////////
        //                            //
        // not_expression             //
        //                            //
        ////////////////////////////////

        inline not_expression::not_expression(conditional_expression* expr)
          : _M_expr(expr)
        {
        }

        inline not_expression::~not_expression()
        {
          delete _M_expr;
        }

        inline
        bool not_expression::evaluate(const icmp& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool not_expression::evaluate(const udp& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool not_expression::evaluate(const dns& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool not_expression::evaluate(const tcp_begin& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool not_expression::evaluate(const tcp_data& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        inline
        bool not_expression::evaluate(const tcp_end& ev,
                                      const char* srchostname,
                                      const char* desthostname) const
        {
          return evaluate_(ev, srchostname, desthostname);
        }

        template<typename Event>
        inline
        bool not_expression::evaluate_(const Event& ev,
                                       const char* srchostname,
                                       const char* desthostname) const
        {
          return !_M_expr->evaluate(ev, srchostname, desthostname);
        }


        ////////////////////////////////
        //                            //
        // event_expression           //
        //                            //
        ////////////////////////////////

        inline void event_expression::init(identifier id, uint64_t n)
        {
          _M_identifier = id;
          _M_number = n;
        }

        inline bool event_expression::init(identifier id,
                                           const char* s,
                                           size_t len)
        {
          if (len < sizeof(_M_str)) {
            _M_identifier = id;

            memcpy(_M_str, s, len);
            _M_str[len] = 0;

            _M_strlen = len;

            return true;
          }

          return false;
        }

        inline void event_expression::init(identifier id, const mask& netmask)
        {
          _M_identifier = id;
          _M_netmask = netmask;
        }

        inline identifier event_expression::id() const
        {
          return _M_identifier;
        }

        inline uint64_t event_expression::number() const
        {
          return _M_number;
        }

        inline const char* event_expression::string() const
        {
          return _M_str;
        }

        inline size_t event_expression::string_length() const
        {
          return _M_strlen;
        }

        inline const mask& event_expression::netmask() const
        {
          return _M_netmask;
        }


        ////////////////////////////////
        //                            //
        // equality_expression        //
        //                            //
        ////////////////////////////////

        inline equality_expression::equality_expression(equality_operator op)
          : _M_operator(op)
        {
        }

        inline
        bool equality_expression::evaluate_event_type(event::type type) const
        {
          return evaluate_number(static_cast<uint64_t>(type));
        }

        template<typename Event>
        inline
        bool equality_expression::evaluate_source_ip(const Event& ev) const
        {
          bool res = ip_match(netmask(), ev.saddr, ev.addrlen);

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        template<typename Event>
        inline
        bool equality_expression::evaluate_destination_ip(const Event& ev) const
        {
          bool res = ip_match(netmask(), ev.daddr, ev.addrlen);

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        template<typename Event>
        inline
        bool equality_expression::evaluate_ip(const Event& ev) const
        {
          bool res = ((ip_match(netmask(), ev.saddr, ev.addrlen)) ||
                      (ip_match(netmask(), ev.daddr, ev.addrlen)));

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        inline
        bool equality_expression::evaluate_hostname(const char* hostname) const
        {
          bool res = ((hostname) && (strcasestr(hostname, string())));

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        inline bool equality_expression::
        evaluate_hostnames(const char* srchostname,
                           const char* desthostname) const
        {
          bool res = (((srchostname) && (strcasestr(srchostname, string()))) ||
                      ((desthostname) && (strcasestr(desthostname, string()))));

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        template<typename Event>
        inline
        bool equality_expression::evaluate_port(const Event& ev) const
        {
          bool res = ((ev.sport == number()) || (ev.dport == number()));

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        inline bool equality_expression::evaluate_number(uint64_t n) const
        {
          bool res = (n == number());

          return (_M_operator == equality_operator::equal_to) ? res : !res;
        }

        inline bool equality_expression::ip_match(const mask& netmask,
                                                  const void* addr,
                                                  size_t len)
        {
          return netmask.match(addr, len);
        }


        ////////////////////////////////
        //                            //
        // relational_expression      //
        //                            //
        ////////////////////////////////

        inline
        relational_expression::relational_expression(relational_operator op)
          : _M_operator(op)
        {
        }

        template<typename Event>
        inline
        bool relational_expression::evaluate_port(const Event& ev) const
        {
          switch (_M_operator) {
            case relational_operator::less:
              return ((ev.sport < number()) || (ev.dport < number()));
            case relational_operator::greater:
              return ((ev.sport > number()) || (ev.dport > number()));
            case relational_operator::less_or_equal:
              return ((ev.sport <= number()) || (ev.dport <= number()));
            case relational_operator::greater_or_equal:
              return ((ev.sport >= number()) || (ev.dport >= number()));
            default:
              return false;
          }
        }

        inline bool relational_expression::evaluate_number(uint64_t n) const
        {
          switch (_M_operator) {
            case relational_operator::less:
              return (n < number());
            case relational_operator::greater:
              return (n > number());
            case relational_operator::less_or_equal:
              return (n <= number());
            case relational_operator::greater_or_equal:
              return (n >= number());
            default:
              return false;
          }
        }
      }
    }
  }
}

#endif // NET_MON_EVENT_GRAMMAR_EXPRESSIONS_H
