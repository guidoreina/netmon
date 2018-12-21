#include <stdlib.h>
#include <stdio.h>
#include "net/mon/event/merger.h"

int main(int argc, const char** argv)
{
  if (argc >= 4) {
    net::mon::event::merger evmerger;
    if (evmerger.merge(argv + 1, argc - 2, argv[argc - 1])) {
      return 0;
    } else {
      fprintf(stderr, "Error merging files.\n");
    }
  } else {
    fprintf(stderr,
            "Usage: %s <input-event-file> ... <input-event-file> "
            "<output-event-file>\n",
            argv[0]);
  }

  return -1;
}
