#ifndef NET_MON_DNS_INVERTED_CACHE_H
#define NET_MON_DNS_INVERTED_CACHE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "util/node.h"
#include "string/buffer.h"

namespace net {
  namespace mon {
    namespace dns {
      // DNS inverted cache.
      template<typename Address>
      class inverted_cache {
        public:
          // Minimum size of the hash table (256).
          static constexpr const size_t min_size = static_cast<size_t>(1) << 8;

          // Maximum size of the hash table (4294967296 [64bit], 65536 [32bit]).
          static constexpr const size_t
                 max_size = static_cast<size_t>(1) << (4 * sizeof(size_t));

          // Default size of the hash table (4096).
          static constexpr const size_t
                 default_size = static_cast<size_t>(1) << 12;

          typedef Address address_type;

          // Constructor.
          inverted_cache() = default;

          // Destructor.
          ~inverted_cache();

          // Clear.
          void clear();

          // Initialize.
          bool init(size_t size);

          // Add.
          bool add(const address_type& addr, const char* host, uint8_t hostlen);

          // Get host.
          const char* host(const address_type& addr) const;

        private:
          static constexpr const size_t entry_allocation = 1024;

          // Buffer where to store the hostnames.
          string::buffer _M_buf;

          struct entry : private util::node {
            friend class inverted_cache;

            address_type addr;

            size_t host;
            uint8_t hostlen;
          };

          // Hash table.
          util::node* _M_entries = nullptr;

          // Size of the hash table.
          size_t _M_size = 0;

          // Mask (for performing modulo).
          size_t _M_mask;

          // Free entries.
          entry* _M_free = nullptr;

          // Erase entries.
          static void erase(util::node* header);

          // Get free entry.
          entry* get_free_entry();

          // Allocate entries.
          bool allocate_entries(size_t count);

          // Disable copy constructor and assignment operator.
          inverted_cache(const inverted_cache&) = delete;
          inverted_cache& operator=(const inverted_cache&) = delete;
      };

      template<typename Address>
      inline inverted_cache<Address>::~inverted_cache()
      {
        clear();
      }

      template<typename Address>
      void inverted_cache<Address>::clear()
      {
        if (_M_entries) {
          for (size_t i = 0; i < _M_size; i++) {
            erase(&_M_entries[i]);
          }

          free(_M_entries);
          _M_entries = nullptr;
        }

        _M_size = 0;

        while (_M_free) {
          entry* next = static_cast<entry*>(_M_free->next);

          free(_M_free);

          _M_free = next;
        }

        _M_buf.clear();
      }

      template<typename Address>
      bool inverted_cache<Address>::init(size_t size)
      {
        if ((size >= min_size) &&
            (size <= max_size) &&
            ((size & (size - 1)) == 0)) {
          // Allocate memory for the entries.
          if ((_M_entries = static_cast<util::node*>(
                              malloc(size * sizeof(util::node))
                            )) != nullptr) {
            for (size_t i = 0; i < size; i++) {
              _M_entries[i].prev = &_M_entries[i];
              _M_entries[i].next = &_M_entries[i];
            }

            // Allocate free entries.
            if (allocate_entries(entry_allocation)) {
              _M_size = size;
              _M_mask = size - 1;

              return true;
            }
          }
        }

        return false;
      }

      template<typename Address>
      bool inverted_cache<Address>::add(const address_type& addr,
                                        const char* host,
                                        uint8_t hostlen)
      {
        uint32_t bucket = addr.hash() & _M_mask;

        // Search entry.
        util::node* header = &_M_entries[bucket];
        entry* e = static_cast<entry*>(header->next);

        while (e != header) {
          // If it is the entry we are looking for...
          if (addr == e->addr) {
            // If the host has not changed...
            if ((hostlen == e->hostlen) &&
                (strncasecmp(host, _M_buf.data() + e->host, hostlen) == 0)) {
              return true;
            }

            size_t off = _M_buf.length();

            if ((_M_buf.append(host, hostlen)) && (_M_buf.append('\0'))) {
              // Update host.
              e->host = off;
              e->hostlen = hostlen;

              return true;
            } else {
              return false;
            }
          }

          e = static_cast<entry*>(e->next);
        }

        // Entry not found.

        size_t off = _M_buf.length();

        if (((e = get_free_entry()) != nullptr) &&
            (_M_buf.append(host, hostlen)) &&
            (_M_buf.append('\0'))) {
          e->prev = header;
          e->next = header->next;

          header->next->prev = e;
          header->next = e;

          e->addr = addr;
          e->host = off;
          e->hostlen = hostlen;

          return true;
        }

        return false;
      }

      template<typename Address>
      const char* inverted_cache<Address>::host(const address_type& addr) const
      {
        uint32_t bucket = addr.hash() & _M_mask;

        // Search entry.
        const util::node* header = &_M_entries[bucket];
        const entry* e = static_cast<const entry*>(header->next);

        while (e != header) {
          // If it is the entry we are looking for...
          if (addr == e->addr) {
            return _M_buf.data() + e->host;
          }

          e = static_cast<const entry*>(e->next);
        }

        // Entry not found.
        return nullptr;
      }

      template<typename Address>
      inline void inverted_cache<Address>::erase(util::node* header)
      {
        util::node* n = header->next;

        while (n != header) {
          util::node* next = n->next;

          free(n);

          n = next;
        }
      }

      template<typename Address>
      inline typename inverted_cache<Address>::entry*
      inverted_cache<Address>::get_free_entry()
      {
        if ((_M_free) || (allocate_entries(entry_allocation))) {
          entry* e = _M_free;

          _M_free = static_cast<entry*>(_M_free->next);

          return e;
        }

        return nullptr;
      }

      template<typename Address>
      bool inverted_cache<Address>::allocate_entries(size_t count)
      {
        for (size_t i = 0; i < count; i++) {
          entry* e;
          if ((e = static_cast<entry*>(malloc(sizeof(entry)))) != nullptr) {
            e->next = _M_free;
            _M_free = e;
          } else {
            return (_M_free != nullptr);
          }
        }

        return true;
      }
    }
  }
}

#endif // NET_MON_DNS_INVERTED_CACHE_H
