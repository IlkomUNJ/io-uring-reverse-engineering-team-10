// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

// Prepares a futex operation by validating inputs and initializing necessary resources or parameters.
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Similar to io_futex_prep but for vectorized futex operations, handling multiple futexes at once.
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Handles waiting on a single futex, blocking until a wake event or timeout occurs.
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);
// Handles waiting on a vector of futexes, blocking until conditions are met or a timeout occurs.
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);
// Wakes threads waiting on a single futex, signaling them to continue.
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);

#if defined(CONFIG_FUTEX)
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags);
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all);
bool io_futex_cache_init(struct io_ring_ctx *ctx);
void io_futex_cache_free(struct io_ring_ctx *ctx);
#else
// Ensures that any resources or state associated with the futex are cleaned up
static inline int io_futex_cancel(struct io_ring_ctx *ctx,
				  struct io_cancel_data *cd,
				  unsigned int issue_flags)
{
	return 0;
}
// removing all futexes associated with a particular context or resource.
static inline bool io_futex_remove_all(struct io_ring_ctx *ctx,
				       struct io_uring_task *tctx, bool cancel_all)
{
	return false;
}
// Sets up data structures and memory pools needed for efficient futex allocation and management.
static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return false;
}
// Cleans up resources allocated for the futex cache, ensuring no memory leaks occur.
static inline void io_futex_cache_free(struct io_ring_ctx *ctx)
{
}
#endif
