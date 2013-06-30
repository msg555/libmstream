#ifndef _MSTREAM_HEAP_H
#define _MSTREAM_HEAP_H

#include <stddef.h>

typedef int(*compare_func)(void*, void*);
typedef size_t(*to_id_func)(void*);
typedef void(*set_id_func)(void*, size_t);

struct heap {
  compare_func compare;
  to_id_func to_id;
  set_id_func set_id;

  size_t size;
  size_t cap;
  void** heap;
};

void _mstream_heap_init(struct heap* h, compare_func compare,
                        to_id_func to_id, set_id_func set_id);

void _mstream_heap_destroy(struct heap* h);

void _mstream_heap_add(struct heap* h, void* x);

void* _mstream_heap_pop(struct heap* h);

void* _mstream_heap_top(struct heap* h);

void _mstream_heap_remove(struct heap* h, void* x);

void _mstream_heap_adjust(struct heap* h, void* x);

#endif
