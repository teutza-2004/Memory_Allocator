// SPDX-License-Identifier: BSD-3-Clause

#include "functions.h"

block_meta *expand_heap(size_t size, size_t treshold)
{
	block_meta *block = NULL;

	if (size < treshold) {
		if (!last_brk_block) //
			size = HEAP_SIZE - META_SIZE; //
		void *ret = sbrk(size + META_SIZE);

		DIE((ret == (void *)-1), "brk failed");
		block = (block_meta *)ret;
		block->status = STATUS_ALLOC;

		last_brk_block = last_free_block = block;
	} else {
		void *ret = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		DIE((ret == (void *)-1), "mmap failed");
		block = (block_meta *)ret;
		block->status = STATUS_MAPPED;
	}
	block->size = size;
	block->next = NULL;

	block_meta *b = NULL;

	for (b = base_heap; b->next; b = b->next) // parcurg ca sa ajung la sf listei
		;
	b->next = block;
	block->prev = b;
	return block;
}

block_meta *alloc_heap(size_t size, size_t treshold)
{
	if (size < treshold) {
		if (!last_brk_block) //
			size = HEAP_SIZE - META_SIZE; //
		void *ret = sbrk(HEAP_SIZE);

		DIE((ret == (void *)-1), "brk failed");
		base_heap = (block_meta *)ret;
		base_heap->status = STATUS_ALLOC;

		last_brk_block = last_free_block = base_heap;
	} else {
		void *ret = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		DIE((ret == (void *)-1), "mmap failed");
		base_heap = (block_meta *)ret;
		base_heap->status = STATUS_MAPPED;
	}
	base_heap->size = size;
	base_heap->prev = NULL;
	base_heap->next = NULL;
	return base_heap;
}

block_meta *find_free_block(block_meta *base_heap, size_t size)
{
	block_meta *b = NULL; // folosesc pentru parcurgerea heap-ului
	block_meta *best_fit = NULL;

	for (b = base_heap; b; b = b->next) {
		// verific daca poate fi reutilizat
		if ((!best_fit || best_fit->size > b->size) && b->status == STATUS_FREE && b->size >= size) {
			best_fit = b;
		} else if (!best_fit && b->status == STATUS_FREE && b == last_free_block) {
			// cazul in care este ultimul block, il extind
			DIE((sbrk(size - b->size) == (void *)-1), "brk failed");
			b->size = size;
			b->status = STATUS_ALLOC;
			return b;
		}
	}
	if (best_fit) {
		best_fit->status = STATUS_ALLOC;
		return best_fit;
	}
	return NULL;
}

block_meta *split_block(block_meta *block, size_t size)
{
	// verific daca al doilea block ar putea acomoda metadatele si cel putin un byte
	if (block->size < size + META_SIZE + 8)
		return block;

	// al doilea block, pe care il adaug la lista (care ramane gol)
	block_meta *new_block = (block_meta *)((char *)block + META_SIZE + size);

	new_block->size = block->size - size - META_SIZE;
	new_block->status = STATUS_FREE;
	new_block->next = block->next;
	new_block->prev = block;

	if (block->next)
		block->next->prev = new_block;

	// primul block (cel alocat acum)
	block->size = size;
	block->next = new_block;

	// actualizez last_brk_block daca e necesar
	if (block == last_brk_block)
		last_brk_block = new_block;
	if (last_free_block < new_block)
		last_free_block = new_block;

	return block;
}

block_meta *coalesce(block_meta *block)
{
	block_meta *next_block = block->next;

	while (next_block) {
		if (next_block->status == STATUS_MAPPED) {
			next_block = next_block->next;
			continue;
		}
		if (next_block->status == STATUS_FREE) {
			if (next_block == last_free_block)
				last_free_block = block;
			block->size += next_block->size + META_SIZE;
			next_block->prev->next = next_block->next;
			if (next_block->next)
				next_block->next->prev = next_block->prev;
			next_block = next_block->next;
		} else {
			break;
		}
	}

	if (block->status == STATUS_FREE) {
		block_meta *prev_block = block->prev;

		while (prev_block) {
			if (prev_block->status == STATUS_MAPPED) {
				prev_block = prev_block->prev;
				continue;
			}
			if (prev_block->status == STATUS_FREE) {
				if (block == last_free_block)
					last_free_block = prev_block;
				prev_block->size += block->size + META_SIZE;
				block->prev->next = block->next;
				if (block->next)
					block->next->prev = block->prev;
				block = prev_block;
				prev_block = block->prev;
			} else {
				break;
			}
		}
	}

	return block;
}
