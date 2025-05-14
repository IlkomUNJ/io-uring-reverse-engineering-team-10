// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_KBUF_H
#define IOU_KBUF_H

#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>

enum {
	/* ring mapped provided buffers */
	IOBL_BUF_RING	= 1,
	/* buffers are consumed incrementally rather than always fully */
	IOBL_INC	= 2,
};

struct io_buffer_list {
	/*
	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not,
	 * then these are classic provided buffers and ->buf_list is used.
	 */
	union {
		struct list_head buf_list;
		struct io_uring_buf_ring *buf_ring;
	};
	__u16 bgid;

	/* below is for ring provided buffers */
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;

	__u16 flags;

	struct io_mapped_region region;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

enum {
	/* can alloc a bigger vec */
	KBUF_MODE_EXPAND	= 1,
	/* if bigger vec allocated, free old one */
	KBUF_MODE_FREE		= 2,
};

struct buf_sel_arg {
	struct iovec *iovs;
	size_t out_len;
	size_t max_len;
	unsigned short nr_iovs;
	unsigned short mode;
};

// General buffer selection function, picking the appropriate kernel or user buffer for an operation.
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);
// determines the most appropriate buffer(s) based on the context, such as the size of the data and the availability of buffers.
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags);
// Similar to io_ring_buffers_peek, but applies to generic I/O buffers.
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);
// Destroys a set of buffers, ensuring all resources are released and no references remain.
void io_destroy_buffers(struct io_ring_ctx *ctx);

// Prepares for removing buffers, validating the operation and setting up prerequisites.
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the removal of buffers, cleaning them from the system or user space.
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Prepares to provide buffers for use, setting up structures and allocating space.
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Completes the process of providing buffers, making them available for immediate use.
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Registers a ring buffer for kernel or user space use, linking it to a specific I/O context.
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
// Unregisters a ring buffer, detaching it from the context and cleaning up.
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);
// Registers the status of a provided buffer, marking its availability or completion state.
int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);

// Recycles a legacy kernel buffer, returning it to a reusable state for efficiency.
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);
// Removes or discards a legacy kernel buffer, freeing associated resources.
void io_kbuf_drop_legacy(struct io_kiocb *req);

// Internal function for releasing generic kernel buffers, cleaning up resources.
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs);
// Commits kernel buffer operations, marking them as complete and ready for further processing.
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr);

// Retrieves a mapped memory region for a provided buffer, linking it to user or kernel space.			
struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid);

// Recycles a legacy kernel buffer, returning it to a reusable state for efficiency.
static inline bool io_kbuf_recycle_ring(struct io_kiocb *req)
{
	/*
	 * We don't need to recycle for REQ_F_BUFFER_RING, we can just clear
	 * the flag and hence ensure that bl->head doesn't get incremented.
	 * If the tail has already been incremented, hang on to it.
	 * The exception is partial io, that case we should increment bl->head
	 * to monopolize the buffer.
	 */
	if (req->buf_list) {
		req->buf_index = req->buf_list->bgid;
		req->flags &= ~(REQ_F_BUFFER_RING|REQ_F_BUFFERS_COMMIT);
		return true;
	}
	return false;
}

// handles the actual logic of selecting an appropriate buffer for an I/O operation.
static inline bool io_do_buffer_select(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return false;
	return !(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING));
}

// Returns a previously used kernel buffer to a reusable state, allowing it 
// to be efficiently allocated for future operations without reinitializing from scratch.
static inline bool io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
	if (req->flags & REQ_F_BL_NO_RECYCLE)
		return false;
	if (req->flags & REQ_F_BUFFER_SELECTED)
		return io_kbuf_recycle_legacy(req, issue_flags);
	if (req->flags & REQ_F_BUFFER_RING)
		return io_kbuf_recycle_ring(req);
	return false;
}

// Frees the buffer or marks it as available for reuse, ensuring proper resource management.
static inline unsigned int io_put_kbuf(struct io_kiocb *req, int len,
				       unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, 1);
}

//  Handles batch release of buffers, optimizing performance when cleaning up after multi-buffer operations.
static inline unsigned int io_put_kbufs(struct io_kiocb *req, int len,
					int nbufs, unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, nbufs);
}
#endif
