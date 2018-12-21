#ifndef UTIL_NODE_H
#define UTIL_NODE_H

namespace util {
  struct node {
    struct node* prev;
    struct node* next;
  };
}

#endif // UTIL_NODE_H
