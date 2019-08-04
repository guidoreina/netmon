#include <stdlib.h>
#include <stdio.h>
#include "net/mon/event/printer/db/sqlite.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

bool net::mon::event::printer::db::sqlite::close()
{
  // If the database has been opened...
  if (_M_db) {
    // Finalize statements.
    for (size_t i = 0; i < 6; i++) {
      if (_M_statements[i]) {
        sqlite3_finalize(_M_statements[i]);
        _M_statements[i] = nullptr;
      }
    }

    // Close database.
    if (sqlite3_close(_M_db) == SQLITE_OK) {
      _M_db = nullptr;
    } else {
      return false;
    }
  }

  return true;
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::icmp& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 0;

  if ((bind(idx, ev, srchost, dsthost)) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          6,
                          ev.icmp_type) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          7,
                          ev.icmp_code) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          8,
                          ev.transferred) == SQLITE_OK)) {
    sqlite3_step(_M_statements[idx]);
  }
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::udp& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 1;

  if ((bind(idx, ev, srchost, dsthost)) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          6,
                          ev.sport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          7,
                          ev.dport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          8,
                          ev.transferred) == SQLITE_OK)) {
    sqlite3_step(_M_statements[idx]);
  }
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::dns& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 2;

  // If it is a DNS response...
  if (ev.nresponses > 0) {
    if ((bind(idx, ev)) &&
        (sqlite3_bind_int64(_M_statements[idx],
                            4,
                            ev.sport) == SQLITE_OK) &&
        (sqlite3_bind_int64(_M_statements[idx],
                            5,
                            ev.dport) == SQLITE_OK) &&
        (sqlite3_bind_int64(_M_statements[idx],
                            6,
                            ev.transferred) == SQLITE_OK) &&
        (sqlite3_bind_int64(_M_statements[idx],
                            7,
                            ev.qtype) == SQLITE_OK) &&
        (sqlite3_bind_text(_M_statements[idx],
                           8,
                           ev.domain,
                           ev.domainlen,
                           SQLITE_STATIC) == SQLITE_OK)) {
      // For each IP address...
      for (size_t i = 0; i < ev.nresponses; i++) {
        char ip[INET6_ADDRSTRLEN];
        if (ev.responses[i].addrlen == 4) {
          if (!inet_ntop(AF_INET, ev.responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        } else {
          if (!inet_ntop(AF_INET6, ev.responses[i].addr, ip, sizeof(ip))) {
            continue;
          }
        }

        if (i > 0) {
          sqlite3_reset(_M_statements[idx]);
        }

        if (sqlite3_bind_text(_M_statements[idx],
                              9,
                              ip,
                              -1,
                              SQLITE_STATIC) == SQLITE_OK) {
          sqlite3_step(_M_statements[idx]);
        }
      }
    }
  }
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::tcp_begin& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 3;

  if ((bind(idx, ev, srchost, dsthost)) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          6,
                          ev.sport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          7,
                          ev.dport) == SQLITE_OK)) {
    sqlite3_step(_M_statements[idx]);
  }
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::tcp_data& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 4;

  if ((bind(idx, ev, srchost, dsthost)) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          6,
                          ev.sport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          7,
                          ev.dport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          8,
                          ev.creation) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          9,
                          ev.payload) == SQLITE_OK)) {
    sqlite3_step(_M_statements[idx]);
  }
}

void
net::mon::event::printer::db::sqlite::print(uint64_t nevent,
                                            const event::tcp_end& ev,
                                            const char* srchost,
                                            const char* dsthost)
{
  static constexpr const size_t idx = 5;

  if ((bind(idx, ev, srchost, dsthost)) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          6,
                          ev.sport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          7,
                          ev.dport) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          8,
                          ev.creation) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          9,
                          ev.transferred_client) == SQLITE_OK) &&
      (sqlite3_bind_int64(_M_statements[idx],
                          10,
                          ev.transferred_server) == SQLITE_OK)) {
    sqlite3_step(_M_statements[idx]);
  }
}

bool net::mon::event::printer::db::sqlite::create_tables()
{
  static constexpr const char* const commands =
    "CREATE TABLE icmp(timestamp            INTEGER NOT NULL,"
                      "source_address       TEXT    NOT NULL,"
                      "destination_address  TEXT    NOT NULL,"
                      "source_hostname      TEXT,"
                      "destination_hostname TEXT,"
                      "icmp_type            INTEGER NOT NULL,"
                      "icmp_code            INTEGER NOT NULL,"
                      "transferred          INTEGER NOT NULL);"

    "CREATE TABLE udp(timestamp            INTEGER NOT NULL,"
                     "source_address       TEXT    NOT NULL,"
                     "destination_address  TEXT    NOT NULL,"
                     "source_hostname      TEXT,"
                     "destination_hostname TEXT,"
                     "source_port          INTEGER NOT NULL,"
                     "destination_port     INTEGER NOT NULL,"
                     "transferred          INTEGER NOT NULL);"

    "CREATE TABLE dns(timestamp            INTEGER NOT NULL,"
                     "source_address       TEXT    NOT NULL,"
                     "destination_address  TEXT    NOT NULL,"
                     "source_port          INTEGER NOT NULL,"
                     "destination_port     INTEGER NOT NULL,"
                     "transferred          INTEGER NOT NULL,"
                     "query_type           INTEGER NOT NULL,"
                     "domain               TEXT    NOT NULL,"
                     "ip_address           TEXT    NOT NULL);"

    "CREATE TABLE tcp_begin(timestamp            INTEGER NOT NULL,"
                           "source_address       TEXT    NOT NULL,"
                           "destination_address  TEXT    NOT NULL,"
                           "source_hostname      TEXT,"
                           "destination_hostname TEXT,"
                           "source_port          INTEGER NOT NULL,"
                           "destination_port     INTEGER NOT NULL);"

    "CREATE TABLE tcp_data(timestamp            INTEGER NOT NULL,"
                          "source_address       TEXT    NOT NULL,"
                          "destination_address  TEXT    NOT NULL,"
                          "source_hostname      TEXT,"
                          "destination_hostname TEXT,"
                          "source_port          INTEGER NOT NULL,"
                          "destination_port     INTEGER NOT NULL,"
                          "creation             INTEGER NOT NULL,"
                          "payload              INTEGER NOT NULL);"

    "CREATE TABLE tcp_end(timestamp            INTEGER NOT NULL,"
                         "source_address       TEXT    NOT NULL,"
                         "destination_address  TEXT    NOT NULL,"
                         "source_hostname      TEXT,"
                         "destination_hostname TEXT,"
                         "source_port          INTEGER NOT NULL,"
                         "destination_port     INTEGER NOT NULL,"
                         "creation             INTEGER NOT NULL,"
                         "transferred_client   INTEGER NOT NULL,"
                         "transferred_server   INTEGER NOT NULL);";

  // Execute statements.
  return (sqlite3_exec(_M_db,
                       commands,
                       nullptr,
                       nullptr,
                       nullptr) == SQLITE_OK);
}

bool net::mon::event::printer::db::sqlite::create_indices()
{
  static constexpr const char* const commands =
    "CREATE INDEX idx_icmp_timestamp ON icmp(timestamp);"

    "CREATE INDEX idx_udp_timestamp ON udp(timestamp);"

    "CREATE INDEX idx_dns_timestamp ON dns(timestamp);"

    "CREATE INDEX idx_tcp_begin_timestamp ON tcp_begin(timestamp);"
    "CREATE INDEX idx_tcp_begin_source_address ON tcp_begin(source_address);"
    "CREATE INDEX idx_tcp_begin_destination_hostname "
                  "ON tcp_begin(destination_hostname);"

    "CREATE INDEX idx_tcp_data_timestamp ON tcp_data(timestamp);"
    "CREATE INDEX idx_tcp_data_creation ON tcp_data(creation);"

    "CREATE INDEX idx_tcp_end_timestamp ON tcp_end(timestamp);";

  // Execute statements.
  return (sqlite3_exec(_M_db,
                       commands,
                       nullptr,
                       nullptr,
                       nullptr) == SQLITE_OK);
}

bool net::mon::event::printer::db::sqlite::prepare_statements()
{
  static constexpr const char* const statements[] = {
    "INSERT INTO icmp      VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    "INSERT INTO udp       VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
    "INSERT INTO dns       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "INSERT INTO tcp_begin VALUES(?, ?, ?, ?, ?, ?, ?)",
    "INSERT INTO tcp_data  VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "INSERT INTO tcp_end   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  };

  // Prepare statements.
  for (size_t i = 0; i < ARRAY_SIZE(statements); i++) {
    if (sqlite3_prepare_v2(_M_db,
                           statements[i],
                           -1,
                           &_M_statements[i],
                           nullptr) != SQLITE_OK) {
      return false;
    }
  }

  return true;
}
