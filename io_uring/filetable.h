// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

// Allocates and initializes the file tables needed for managing I/O operations
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);
// Frees and cleans up the file tables, releasing memory and resources used to manage fixed file descriptors
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);
// Installs a fixed file descriptor into the file table at a specific location, associating it with an open file or resource.
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);
// performs the actual installation of a fixed file descriptor in the file table, typically called by higher-level wrappers.
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);
// Removes a fixed file descriptor from the file table, cleaning up its entry and releasing associated resources.
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);
// Registers a range of fixed file descriptors for allocation, setting up a section of the file table for use by I/O operations.
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);
// Retrieves the flags for a given file descriptor or file slot, indicating 
// properties such as access modes, permissions, or operational states.
io_req_flags_t io_file_get_flags(struct file *file);

//  clearing a specific bit in the file descriptor bitmap, marking a file descriptor as free or unused.
static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}

// setting a specific bit in the file descriptor bitmap, marking a file descriptor as allocated or in use.
static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));
	__set_bit(bit, table->bitmap);
	table->alloc_hint = bit + 1;
}

#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

// retrieve or manage flags associated with a specific file slot, indicating its status or properties.
static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{

	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

// access the file structure associated with a specific file slot, allowing interaction with the file or resource.
static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}

// setting or associating a file structure with a fixed file descriptor in the file table.
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

// registering a range of file descriptors in the file table for allocation, 
// specifying the boundaries for fixed descriptor management.
static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif
