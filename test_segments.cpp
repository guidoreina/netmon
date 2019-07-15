#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include "net/mon/tcp/segments.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

static void payloadfn(const void*, size_t, void*);
static void gapfn(size_t, void*);

int main()
{
  struct segment {
    uint32_t seqno;
    const char* payload;
    size_t len;
  };

  net::mon::tcp::segments segments;
  if (segments.create(payloadfn, gapfn)) {
    {
      segments.next_sequence_number(0);

      static constexpr const segment segs[] = {
        {25, "Z0123", 5},
        {15, "PQRST", 5},
        {10, "KLMNO", 5},
        { 5, "FGHIJ", 5},
        { 0, "ABCDE", 5}
      };

      for (size_t i = 0; i < ARRAY_SIZE(segs); i++) {
        if (!segments.add(segs[i].seqno, segs[i].payload, segs[i].len)) {
          fprintf(stderr, "Error adding segment %zu.\n", i + 1);
          return -1;
        }
      }

      segments.fin();

      printf("========================================\n");
    }

    {
      segments.clear();
      segments.next_sequence_number(UINT_MAX - 2);

      static constexpr const segment segs[] = {
        {          22, "Z0123", 5},
        {          12, "PQRST", 5},
        {           7, "KLMNO", 5},
        {           2, "FGHIJ", 5},
        {UINT_MAX - 2, "ABCDE", 5}
      };

      for (size_t i = 0; i < ARRAY_SIZE(segs); i++) {
        if (!segments.add(segs[i].seqno, segs[i].payload, segs[i].len)) {
          fprintf(stderr, "Error adding segment %zu.\n", i + 1);
          return -1;
        }
      }

      segments.fin();

      printf("========================================\n");
    }

    {
      segments.clear();
      segments.next_sequence_number(UINT_MAX - 2);

      static constexpr const segment segs[] = {
        {UINT_MAX - 2, "ABCDE", 5},
        {           2, "FGHIJ", 5},
        {           7, "KLMNO", 5},
        {          12, "PQRST", 5},
        {          22, "Z0123", 5}
      };

      for (size_t i = 0; i < ARRAY_SIZE(segs); i++) {
        if (!segments.add(segs[i].seqno, segs[i].payload, segs[i].len)) {
          fprintf(stderr, "Error adding segment %zu.\n", i + 1);
          return -1;
        }
      }

      segments.fin();
    }

    return 0;
  } else {
    fprintf(stderr, "Error creating segments.\n");
  }

  return -1;
}

void payloadfn(const void* payload, size_t len, void* user)
{
  printf("[Payload] Length: %zu, ", len);

  for (size_t i = 0; i < len; i++) {
    printf("%c", static_cast<const char*>(payload)[i]);
  }

  printf("\n");
}

void gapfn(size_t len, void* user)
{
  printf("[Gap] Length: %zu\n", len);
}
