#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "net/mon/event/reader.h"
#include "net/mon/event/printer/human_readable.h"
#include "net/mon/event/printer/json.h"
#include "net/mon/event/printer/csv.h"
#include "net/mon/event/grammar/parser.h"

#if HAVE_SQLITE
  #include "net/mon/event/printer/db/sqlite.h"
#endif

enum class output {
  header,
  human_readable,
  json,
  javascript,
  csv

#if HAVE_SQLITE
  , sqlite
#endif
};

static constexpr const output default_output = output::human_readable;

static constexpr const net::mon::event::printer::format
       default_format = net::mon::event::printer::format::pretty_print;

static
bool parse_arguments(int argc,
                     const char** argv,
                     const char*& infilename,
                     const char*& outfilename,
                     output& out,
                     net::mon::event::printer::format& fmt,
                     char& csv_separator,
                     net::mon::event::grammar::conditional_expression*& filter);

static int print_header(const char* infilename, const char* outfilename);

template<typename Printer>
static int
process_events(Printer& evprinter,
               const char* infilename,
               const char* outfilename,
               const net::mon::event::grammar::conditional_expression* filter);

static void usage(const char* program);

int main(int argc, const char** argv)
{
  const char* infilename;
  const char* outfilename;
  output out;
  net::mon::event::printer::format fmt;
  char csv_separator;
  net::mon::event::grammar::conditional_expression* filter;

  // Parse command-line arguments.
  if (parse_arguments(argc,
                      argv,
                      infilename,
                      outfilename,
                      out,
                      fmt,
                      csv_separator,
                      filter)) {
    memory::unique_ptr<net::mon::event::grammar::conditional_expression>
      f(filter);

    switch (out) {
      case output::header:
        return print_header(infilename, outfilename);
      case output::human_readable:
        {
          net::mon::event::printer::human_readable evprinter(fmt);
          return process_events(evprinter, infilename, outfilename, filter);
        }
      case output::json:
        {
          net::mon::event::printer::json evprinter(fmt);
          return process_events(evprinter, infilename, outfilename, filter);
        }
      case output::javascript:
        {
          net::mon::event::printer::json evprinter(fmt,
                                                   "let jsonEvents = ",
                                                   ";");

          return process_events(evprinter, infilename, outfilename, filter);
        }
      case output::csv:
#if !HAVE_SQLITE
      default:
#endif
        {
          net::mon::event::printer::csv evprinter(csv_separator);
          return process_events(evprinter, infilename, outfilename, filter);
        }
#if HAVE_SQLITE
      default:
        {
          static constexpr const char* const default_name = "events.db";

          const char* const filename = outfilename ? outfilename : default_name;

          net::mon::event::printer::db::sqlite evprinter;

          // Open database.
          if (evprinter.open(filename)) {
            // Initialize database.
            if (evprinter.init()) {
              return process_events(evprinter, infilename, nullptr, filter);
            } else {
              fprintf(stderr, "Error initializing database.\n");
            }
          } else {
            fprintf(stderr, "Error opening database '%s'.\n", filename);
          }

          if (filter) {
            delete filter;
          }

          return -1;
        }
#endif // HAVE_SQLITE
    }
  }

  if (filter) {
    delete filter;
  }

  usage(argv[0]);

  return -1;
}

bool parse_arguments(int argc,
                     const char** argv,
                     const char*& infilename,
                     const char*& outfilename,
                     output& out,
                     net::mon::event::printer::format& fmt,
                     char& csv_separator,
                     net::mon::event::grammar::conditional_expression*& filter)
{
  // Set default values.
  infilename = nullptr;
  outfilename = nullptr;
  out = default_output;
  fmt = default_format;
  csv_separator = net::mon::event::printer::csv::default_separator;
  filter = nullptr;

  bool have_output = false;
  bool have_format = false;
  bool have_csv_separator = false;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--input-filename") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the input filename has not been already set...
        if (!infilename) {
          infilename = argv[i + 1];
          i += 2;
        } else {
          fprintf(stderr, "\"--input-filename\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected input filename after \"--input-filename\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--output-filename") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the output filename has not been already set...
        if (!outfilename) {
          outfilename = argv[i + 1];
          i += 2;
        } else {
          fprintf(stderr, "\"--output-filename\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected output filename after \"--output-filename\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--output") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the output has not been already set...
        if (!have_output) {
          if (strcasecmp(argv[i + 1], "header") == 0) {
            out = output::header;
          } else if (strcasecmp(argv[i + 1], "human-readable") == 0) {
            out = output::human_readable;
          } else if (strcasecmp(argv[i + 1], "json") == 0) {
            out = output::json;
          } else if (strcasecmp(argv[i + 1], "javascript") == 0) {
            out = output::javascript;
          } else if (strcasecmp(argv[i + 1], "csv") == 0) {
            out = output::csv;
#if HAVE_SQLITE
          } else if (strcasecmp(argv[i + 1], "sqlite") == 0) {
            out = output::sqlite;
#endif // HAVE_SQLITE
          } else {
            fprintf(stderr, "Invalid output '%s'.\n\n", argv[i + 1]);
            return false;
          }

          have_output = true;
          i += 2;
        } else {
          fprintf(stderr, "\"--output\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr, "Expected output after \"--output\".\n\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--format") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the format has not been already set...
        if (!have_format) {
          if (strcasecmp(argv[i + 1], "pretty-print") == 0) {
            fmt = net::mon::event::printer::format::pretty_print;
          } else if (strcasecmp(argv[i + 1], "compact") == 0) {
            fmt = net::mon::event::printer::format::compact;
          } else {
            fprintf(stderr, "Invalid format '%s'.\n\n", argv[i + 1]);
            return false;
          }

          have_format = true;
          i += 2;
        } else {
          fprintf(stderr, "\"--format\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr, "Expected format after \"--format\".\n\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--csv-separator") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the CSV separator has not been already set...
        if (!have_csv_separator) {
          if (!argv[i + 1][1]) {
            csv_separator = argv[i + 1][0];

            have_csv_separator = true;
            i += 2;
          } else {
            fprintf(stderr,
                    "Invalid CSV separator '%s' (expected only one character)."
                    "\n\n",
                    argv[i + 1]);

            return false;
          }
        } else {
          fprintf(stderr, "\"--csv-separator\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr,
                "Expected CSV separator after \"--csv-separator\".\n\n");

        return false;
      }
    } else if (strcasecmp(argv[i], "--filter") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        // If the filter has not been already set...
        if (!filter) {
          if ((filter = net::mon::event::grammar::parser::parse(argv[i + 1])) !=
              nullptr) {
            i += 2;
          } else {
            fprintf(stderr, "Invalid filter '%s'.\n\n", argv[i + 1]);
            return false;
          }
        } else {
          fprintf(stderr, "\"--filter\" appears more than once.\n\n");
          return false;
        }
      } else {
        fprintf(stderr, "Expected filter after \"--filter\".\n\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--help") == 0) {
      return false;
    } else {
      fprintf(stderr, "Invalid option \"%s\".\n\n", argv[i]);
      return false;
    }
  }

  if (infilename) {
    return true;
  } else if (argc > 1) {
    fprintf(stderr, "Input filename not set.\n");
  }

  return false;
}

int print_header(const char* infilename, const char* outfilename)
{
  // Open event file.
  net::mon::event::reader evreader;
  if (evreader.open(infilename)) {
    // If an output file has been specified...
    FILE* file;
    if (outfilename) {
      if ((file = fopen(outfilename, "w+")) == nullptr) {
        fprintf(stderr, "Error opening output file '%s'.\n", outfilename);
        return -1;
      }
    } else {
      file = stdout;
    }

    // Print timestamp of the first event.
    time_t sec = evreader.first_timestamp() / 1000000;
    struct tm tm;
    localtime_r(&sec, &tm);

    fprintf(file,
            "First timestamp: %04u/%02u/%02u %02u:%02u:%02u.%06" PRIu64 ".\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            evreader.first_timestamp() % 1000000);

    // Print timestamp of the last event.
    sec = evreader.last_timestamp() / 1000000;
    localtime_r(&sec, &tm);

    fprintf(file,
            "Last timestamp: %04u/%02u/%02u %02u:%02u:%02u.%06" PRIu64 ".\n",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            evreader.last_timestamp() % 1000000);

    if (file != stdout) {
      fclose(file);
    }

    return 0;
  } else {
    fprintf(stderr, "Error opening event file '%s'.\n", infilename);
    return -1;
  }
}

template<typename Printer>
int
process_events(Printer& evprinter,
               const char* infilename,
               const char* outfilename,
               const net::mon::event::grammar::conditional_expression* filter)
{
  // Open event file.
  net::mon::event::reader evreader(&evprinter);
  if (evreader.open(infilename)) {
    // If an output file has been specified...
    if (outfilename) {
      if (!evprinter.open(outfilename)) {
        fprintf(stderr, "Error opening output file '%s'.\n", outfilename);
        return -1;
      }
    } else {
      evprinter.file(stdout);
    }

    // Read events.
    while (evreader.next(filter));

    return 0;
  } else {
    fprintf(stderr, "Error opening event file '%s'.\n", infilename);
    return -1;
  }
}

void usage(const char* program)
{
  fprintf(stderr, "Usage: %s [OPTIONS] --input-filename <filename>\n", program);
  fprintf(stderr, "\n");

  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  --help\n");

  fprintf(stderr, "  --output-filename <filename>\n");
  fprintf(stderr,
          "    <filename>: Name of the file where to save the output.\n");

  fprintf(stderr, "    Default: standard output.\n");

  fprintf(stderr, "  --output <output>\n");
  fprintf(stderr,
          "    <output> ::= \"header\" | \"human-readable\" | \"json\" | "
          "\"javascript\" | \"csv\""
#if HAVE_SQLITE
          " | \"sqlite\""
#endif
          "\n");

  fprintf(stderr, "    Default: \"human-readable\"\n");

  fprintf(stderr, "  --format <format>\n");
  fprintf(stderr, "    <format> ::= \"pretty-print\" | \"compact\"\n");
  fprintf(stderr, "    Default: \"pretty-print\"\n");

  fprintf(stderr, "  --csv-separator <character>\n");
  fprintf(stderr, "    <character>: CSV character separator.\n");
  fprintf(stderr,
          "    Default: '%c'\n",
          net::mon::event::printer::csv::default_separator);

  fprintf(stderr, "  --filter <expression>\n");

  fprintf(stderr, "    <expression> ::= (<expression>)\n");
  fprintf(stderr,
          "    <expression> ::= <expression> <logical-operator> "
          "<expression>\n");

  fprintf(stderr,
          "    <expression> ::= <identifier> <relational-operator> <value>\n");

  fprintf(stderr, "\n");

  fprintf(stderr, "    <logical-operator> ::= \"&&\" | \"||\"\n");

  fprintf(stderr, "\n");

  fprintf(stderr,
          "    <relational-operator> ::= \"==\" | \"!=\" | \"<\" | \">\" | "
          "\"<=\" | \">=\"\n");

  fprintf(stderr, "\n");

  fprintf(stderr,
          "    <identifier> ::= \"date\"                 |\n"
          "                     \"event_type\"           |\n"
          "                     \"source_ip\"            |\n"
          "                     \"source_hostname\"      |\n"
          "                     \"source_port\"          |\n"
          "                     \"destination_ip\"       |\n"
          "                     \"destination_hostname\" |\n"
          "                     \"destination_port\"     |\n"
          "                     \"ip\"                   |\n"
          "                     \"hostname\"             |\n"
          "                     \"port\"                 |\n"
          "                     \"icmp_type\"            |\n"
          "                     \"icmp_code\"            |\n"
          "                     \"transferred\"          |\n"
          "                     \"query_type\"           |\n"
          "                     \"domain\"               |\n"
          "                     \"number_dns_responses\" |\n"
          "                     \"dns_response\"         |\n"
          "                     \"payload\"              |\n"
          "                     \"creation\"             |\n"
          "                     \"duration\"             |\n"
          "                     \"transferred_client\"   |\n"
          "                     \"transferred_server\"\n");

  fprintf(stderr, "\n");

  fprintf(stderr,
          "    <value> ::= <event-type>   |\n"
          "                <number>       |\n"
          "                <string>       |\n"
          "                <timestamp>    |\n"
          "                <hostname>     |\n"
          "                <duration>     |\n"
          "                <network-mask>\n");

  fprintf(stderr, "\n");

  fprintf(stderr,
          "    <event-type> ::= \"icmp\"      |\n"
          "                     \"udp\"       |\n"
          "                     \"dns\"       |\n"
          "                     \"tcp-begin\" |\n"
          "                     \"tcp-data\"  |\n"
          "                     \"tcp-end\"\n");

  fprintf(stderr, "\n");

  fprintf(stderr, "    <string> ::= \"<character>*\"\n");

  fprintf(stderr,
          "    <timestamp> ::= timestamp with the format "
          "YYYY/MM/DD hh:mm:ss[.uuuuuu]\n");

  fprintf(stderr, "    <duration> ::= connection duration in seconds\n");

  fprintf(stderr, "    <network-mask> ::= network address in CIDR notation\n");

  fprintf(stderr, "\n");
}
