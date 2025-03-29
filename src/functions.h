// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <asm-generic/mman-common.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "../utils/block_meta.h"
#include "../utils/osmem.h"
#include "../utils/printf.h"

#define ALIGNMENT 8
#define BLOCK(size) ((size + ALIGNMENT - 1) & ~(ALIGNMENT-1)) // macro pt calcularea zonei+padding

typedef struct block_meta block_meta;

#define HEAP_SIZE (128 * 1024) // 128kb (folosesc si ca mmap treshold)
#define META_SIZE BLOCK(sizeof(block_meta)) // marimea la metadata + padding

extern block_meta *base_heap; // baza heap-ului
extern block_meta *last_brk_block; // ultimul block facut fara mmap
extern block_meta *last_free_block; // ultimul block care este free (coalesce uit)

block_meta *expand_heap(size_t size, size_t treshold);
block_meta *alloc_heap(size_t size, size_t treshold);
block_meta *find_free_block(block_meta *base_heap, size_t size);
block_meta *split_block(block_meta *block, size_t size);
block_meta *coalesce(block_meta *block);
