// SPDX-License-Identifier: BSD-3-Clause

#include "functions.h"

block_meta * base_heap;
block_meta *last_brk_block;
block_meta *last_free_block;

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size <= 0)
		return NULL;

	if (!base_heap) { // heap-ul nu este alocat
		base_heap = alloc_heap(BLOCK(size), HEAP_SIZE);
		if (BLOCK(size) < HEAP_SIZE)
			base_heap = split_block(base_heap, BLOCK(size));
		return (void *)((char *)base_heap + META_SIZE);
	}

	block_meta *block = NULL;

	if (BLOCK(size) < HEAP_SIZE) {
		block = find_free_block(base_heap, BLOCK(size));
		if (block) {
			block = split_block(block, BLOCK(size));
			return (void *)((char *)block + META_SIZE); // pt a putea returna efectiv adresa zonei
		}
	}
	block = expand_heap(BLOCK(size), HEAP_SIZE);
	if (block)
		return (void *)((char *)block + META_SIZE);
	return NULL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;
	block_meta *ptr_block = (block_meta *)((char *)ptr - META_SIZE); // includ si metadatele

	// verific daca este zona mapata
	if (ptr_block->status == STATUS_MAPPED) {
		// scot din lista zona si restabilesc legaturile
		if (ptr_block->prev)
			ptr_block->prev->next = ptr_block->next;
		if (ptr_block->next)
			ptr_block->next->prev = ptr_block->prev;

		if (ptr_block == base_heap) {
			if (base_heap->next)
				base_heap->next->prev = NULL;
			base_heap = NULL;
		}
		DIE((munmap(ptr_block, ptr_block->size + META_SIZE) == -1), "munmap failed");
		return;
	}
	ptr_block->status = STATUS_FREE;
	ptr_block = coalesce(ptr_block);
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	const size_t PAGE_SIZE = getpagesize() - META_SIZE;
	size_t full_size = nmemb * size;

	if (full_size <= 0)
		return NULL;
	if (!base_heap) { // heap-ul nu este alocat
		base_heap = alloc_heap(BLOCK(full_size), PAGE_SIZE);
		if (full_size < PAGE_SIZE)
			base_heap = split_block(base_heap, BLOCK(full_size));
		memset((char *)base_heap + META_SIZE, 0, full_size);
		return (void *)((char *)base_heap + META_SIZE);
	}

	block_meta *block = NULL;

	if (BLOCK(size) < HEAP_SIZE) {
		block = find_free_block(base_heap, BLOCK(full_size));

		if (block && BLOCK(size) < PAGE_SIZE) {
			block = split_block(block, BLOCK(full_size));
			memset((char *)block + META_SIZE, 0, full_size);
			return (void *)((char *)block + META_SIZE); // pt a putea returna efectiv adresa zonei
		}
		if (block)
			block->status = STATUS_FREE;
	}
	block = expand_heap(BLOCK(full_size), PAGE_SIZE);
	if (block) {
		memset((char *)block + META_SIZE, 0, full_size);
		return (void *)((char *)block + META_SIZE);
	}
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (!ptr)
		return os_malloc(size);

	block_meta *ptr_block = (block_meta *)((char *)ptr - META_SIZE); // includ si metadatele

	if (size <= 0) {
		os_free(ptr);
		return NULL;
	}

	// verific daca block-ul e free
	if (ptr_block->status == STATUS_FREE)
		return NULL;

	block_meta *block = NULL;

	// verific daca dau realloc de la o zona mapata
	if (ptr_block->status == STATUS_MAPPED) {
		block = find_free_block(base_heap, BLOCK(size));

		if (!block) {
			if (!last_brk_block && BLOCK(size) < HEAP_SIZE)
				block = expand_heap(HEAP_SIZE - META_SIZE, HEAP_SIZE);
			else
				block = expand_heap(BLOCK(size), HEAP_SIZE);
			if (BLOCK(size) < HEAP_SIZE)
				block = split_block(block, BLOCK(size));
		} else {
			block = split_block(block, BLOCK(size));
		}
		memcpy((char *)block + META_SIZE, ptr, block->size);
		os_free(ptr);
		return (void *)((char *)block + META_SIZE);
	}

	// verific daca zona pe care vreau sa o realloc este mai mare ca size
	if (BLOCK(size) <= ptr_block->size) {
		ptr_block = split_block(ptr_block, BLOCK(size));
		return ptr;
	}

	// verific daca pot da expand la block
	if (ptr_block == last_brk_block) {
		DIE((sbrk(BLOCK(size) - ptr_block->size) == (void *)-1), "brk failed");
		ptr_block->size = BLOCK(size);
		return (void *)((char *)ptr_block + META_SIZE);
	}

	// verific daca pot uni cu zona urmatoare (in cazul in care este free)
	ptr_block = coalesce(ptr_block);
	if (ptr_block->size >= BLOCK(size))
		return (void *)((char *)ptr_block + META_SIZE);

	// pt restul cazurilor efectiv aloc o zona noua si dau free la cea veche / reutilizez zone
	void *new_ptr = os_malloc(size);

	if (new_ptr) {
		memcpy(new_ptr, ptr, ptr_block->size);
		os_free(ptr);
	}
	return new_ptr;
}
