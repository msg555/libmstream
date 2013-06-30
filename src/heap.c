#include "heap.h"

#include <stdlib.h>

static void adjust(struct heap* h, size_t i) {
  void* tmp = h->heap[i];
  for(; i; ) {
    size_t p = (i - 1) >> 1;
    if(!h->compare(h->heap[i], h->heap[p])) {
      break;
    }
    h->heap[i] = h->heap[p];
    h->set_id(h->heap[i], i);
    i = p;
  }

  while((i << 1) + 1 < h->size) {
    size_t c1 = (i << 1) + 1;
    size_t c2 = c1 + 1;
    if(c2 < h->size && h->compare(h->heap[c2], h->heap[c1])) {
      c1 = c2;
    }
    if(!h->compare(h->heap[c1], h->heap[i])) {
      break;
    }
    h->heap[i] = h->heap[c1];
    h->set_id(h->heap[i], i);
    i = c1;
  }

  h->heap[i] = tmp;
  h->set_id(h->heap[i], i);
}

void _mstream_heap_init(struct heap* h, compare_func compare,
                        to_id_func to_id, set_id_func set_id) {
  h->compare = compare;
  h->to_id = to_id;
  h->set_id = set_id;
  h->size = h->cap = 0;
  h->heap = NULL;
}

void _mstream_heap_destroy(struct heap* h) {
  free(h->heap);
}

void _mstream_heap_add(struct heap* h, void* x) {
  if(h->size == h->cap) {
    h->cap = h->cap * 3 / 2 + 4;
    h->heap = (void**)realloc(h->heap, h->cap * sizeof(void*));
  }
  h->heap[h->size++] = x;
  adjust(h, h->size - 1);
}

void* _mstream_heap_pop(struct heap* h) {
  void* x = h->heap[0];
  h->heap[0] = h->heap[--h->size];
  if(h->size) {
    adjust(h, 0);
  }
  return x;
}

void* _mstream_heap_top(struct heap* h) {
  return h->heap[0];
}

void _mstream_heap_remove(struct heap* h, void* x) {
  size_t i = h->to_id(x);
  if(i < h->size && h->heap[i] == x) {
    for(; i; ) {
      size_t p = (i - 1) >> 1;
      h->heap[i] = h->heap[p];
      h->set_id(h->heap[i], i);
      i = p;
    }
    _mstream_heap_pop(h);
  }
}

void _mstream_heap_adjust(struct heap* h, void* x) {
  adjust(h, h->to_id(x));
}
