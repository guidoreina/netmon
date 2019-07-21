#include <arpa/inet.h>
#include "net/mon/event/grammar/expressions.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

namespace net {
  namespace mon {
    namespace event {
      namespace grammar {
        // Identifiers.
        static constexpr const struct {
          const char* name;
          size_t len;

          identifier id;
        } identifiers[] = {
          {"date",                  4, identifier::date                },
          {"event_type",           10, identifier::event_type          },
          {"source_ip",             9, identifier::source_ip           },
          {"source_hostname",      15, identifier::source_hostname     },
          {"source_port",          11, identifier::source_port         },
          {"destination_ip",       14, identifier::destination_ip      },
          {"destination_hostname", 20, identifier::destination_hostname},
          {"destination_port",     16, identifier::destination_port    },
          {"ip",                    2, identifier::ip                  },
          {"hostname",              8, identifier::hostname            },
          {"port",                  4, identifier::port                },
          {"icmp_type",             9, identifier::icmp_type           },
          {"icmp_code",             9, identifier::icmp_code           },
          {"transferred",          11, identifier::transferred         },
          {"query_type",           10, identifier::query_type          },
          {"domain",                6, identifier::domain              },
          {"number_dns_responses", 20, identifier::number_dns_responses},
          {"dns_response",         12, identifier::dns_response        },
          {"payload",               7, identifier::payload             },
          {"creation",              8, identifier::creation            },
          {"duration",              8, identifier::duration            },
          {"transferred_client",   18, identifier::transferred_client  },
          {"transferred_server",   18, identifier::transferred_server  }
        };

        bool from_string(const char* s, size_t len, identifier& id)
        {
          for (size_t i = 0; i < ARRAY_SIZE(identifiers); i++) {
            if ((len == identifiers[i].len) &&
                (strncasecmp(s, identifiers[i].name, len) == 0)) {
              id = identifiers[i].id;
              return true;
            }
          }

          return false;
        }

        const char* to_string(identifier id)
        {
          for (size_t i = 0; i < ARRAY_SIZE(identifiers); i++) {
            if (id == identifiers[i].id) {
              return identifiers[i].name;
            }
          }

          return "(unknown)";
        }

        static inline bool same_string(const char* s1,
                                       size_t len1,
                                       const char* s2,
                                       size_t len2)
        {
          return ((len1 == len2) && (strncasecmp(s1, s2, len1) == 0));
        }


        ////////////////////////////////
        //                            //
        // equality_expression        //
        //                            //
        ////////////////////////////////

        bool equality_expression::evaluate(const icmp& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::icmp);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::icmp_type:
              return evaluate_number(ev.icmp_type);
            case identifier::icmp_code:
              return evaluate_number(ev.icmp_code);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            default:
              return false;
          }
        }

        bool equality_expression::evaluate(const udp& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::udp);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            default:
              return false;
          }
        }

        bool equality_expression::evaluate(const dns& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::dns);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            case identifier::query_type:
              return evaluate_number(ev.qtype);
            case identifier::domain:
              return (_M_operator == equality_operator::equal_to) ?
                       same_string(string(),
                                   string_length(),
                                   ev.domain,
                                   ev.domainlen) :
                       !same_string(string(),
                                    string_length(),
                                    ev.domain,
                                    ev.domainlen);
            case identifier::number_dns_responses:
              return evaluate_number(ev.nresponses);
            case identifier::dns_response:
              return (_M_operator == equality_operator::equal_to) ?
                       have_dns_response(string(), ev) :
                       !have_dns_response(string(), ev);
            default:
              return false;
          }
        }

        bool equality_expression::evaluate(const tcp_begin& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::tcp_begin);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::port:
              return evaluate_port(ev);
            default:
              return false;
          }
        }

        bool equality_expression::evaluate(const tcp_data& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::tcp_data);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::payload:
              return evaluate_number(ev.payload);
            default:
              return false;
          }
        }

        bool equality_expression::evaluate(const tcp_end& ev,
                                           const char* srchostname,
                                           const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::event_type:
              return evaluate_event_type(event::type::tcp_end);
            case identifier::source_ip:
              return evaluate_source_ip(ev);
            case identifier::source_hostname:
              return evaluate_hostname(srchostname);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_ip:
              return evaluate_destination_ip(ev);
            case identifier::destination_hostname:
              return evaluate_hostname(desthostname);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::ip:
              return evaluate_ip(ev);
            case identifier::hostname:
              return evaluate_hostnames(srchostname, desthostname);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::creation:
              return evaluate_number(ev.creation);
            case identifier::duration:
              return evaluate_number(ev.timestamp - ev.creation);
            case identifier::transferred_client:
              return evaluate_number(ev.transferred_client);
            case identifier::transferred_server:
              return evaluate_number(ev.transferred_server);
            default:
              return false;
          }
        }

        bool equality_expression::have_dns_response(const char* ip,
                                                    const dns& ev)
        {
          uint8_t buf[sizeof(struct in6_addr)];
          size_t addrlen;

          if (ip_text_to_binary(ip, buf, addrlen)) {
            for (size_t i = 0; i < ev.nresponses; i++) {
              if ((addrlen == ev.responses[i].addrlen) &&
                  (memcmp(buf, ev.responses[i].addr, addrlen) == 0)) {
                return true;
              }
            }
          }

          return false;
        }

        bool equality_expression::ip_text_to_binary(const char* ip,
                                                    void* addr,
                                                    size_t& addrlen)
        {
          if (inet_pton(AF_INET, ip, addr) == 1) {
            addrlen = 4;
            return true;
          } else if (inet_pton(AF_INET6, ip, addr) == 1) {
            addrlen = 16;
            return true;
          } else {
            return false;
          }
        }


        ////////////////////////////////
        //                            //
        // relational_expression      //
        //                            //
        ////////////////////////////////

        bool relational_expression::evaluate(const icmp& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::icmp_type:
              return evaluate_number(ev.icmp_type);
            case identifier::icmp_code:
              return evaluate_number(ev.icmp_code);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            default:
              return false;
          }
        }

        bool relational_expression::evaluate(const udp& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            default:
              return false;
          }
        }

        bool relational_expression::evaluate(const dns& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::transferred:
              return evaluate_number(ev.transferred);
            case identifier::query_type:
              return evaluate_number(ev.qtype);
            case identifier::number_dns_responses:
              return evaluate_number(ev.nresponses);
            default:
              return false;
          }
        }

        bool relational_expression::evaluate(const tcp_begin& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::port:
              return evaluate_port(ev);
            default:
              return false;
          }
        }

        bool relational_expression::evaluate(const tcp_data& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::payload:
              return evaluate_number(ev.payload);
            default:
              return false;
          }
        }

        bool relational_expression::evaluate(const tcp_end& ev,
                                             const char* srchostname,
                                             const char* desthostname) const
        {
          // Check identifier.
          switch (id()) {
            case identifier::date:
              return evaluate_number(ev.timestamp);
            case identifier::source_port:
              return evaluate_number(ev.sport);
            case identifier::destination_port:
              return evaluate_number(ev.dport);
            case identifier::port:
              return evaluate_port(ev);
            case identifier::creation:
              return evaluate_number(ev.creation);
            case identifier::duration:
              return evaluate_number(ev.timestamp - ev.creation);
            case identifier::transferred_client:
              return evaluate_number(ev.transferred_client);
            case identifier::transferred_server:
              return evaluate_number(ev.transferred_server);
            default:
              return false;
          }
        }
      }
    }
  }
}
