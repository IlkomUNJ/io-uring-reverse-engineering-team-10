// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

#define IO_POLL_ALLOC_CACHE_MAX 32

enum {
	IO_APOLL_OK,
	IO_APOLL_ABORTED,
	IO_APOLL_READY
};

struct io_poll {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	int				retries;
	struct wait_queue_entry		wait;
};

struct async_poll {
	struct io_poll		poll;
	struct io_poll		*double_poll;
};

/*
 * Must only be called inside issue_flags & IO_URING_F_MULTISHOT, or
 * potentially other cases where we already "own" this poll request.
 */
/* Retry multishot poll by incrementing reference count */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
	atomic_inc(&req->poll_refs);
}

/* Prepare poll add request - validate SQE */
int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute poll add operation */
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare poll remove request - validate SQE */
int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute poll remove operation */
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

struct io_cancel_data;
/* Cancel active poll request */
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		   unsigned issue_flags);
/* Arm poll handler for async completion */
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);
/* Remove all poll requests for given context */
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			bool cancel_all);

/* Task work handler for poll completions */
void io_poll_task_func(struct io_kiocb *req, io_tw_token_t tw);
