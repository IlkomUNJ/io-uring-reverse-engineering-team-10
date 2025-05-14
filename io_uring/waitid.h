// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

struct io_waitid_async {
	struct io_kiocb *req;
	struct wait_opts wo;
};

// Execute a waitid request.
// Handles the waitid operation and manages wakeup callbacks.
// Prepare a waitid request for submission.
// Validates the SQE and initializes waitid parameters.
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);
// Cancel a waitid request in the context.
// Handles cancellation based on the provided cancel data.
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);
// Remove all waitid requests for a task.
// Cancels and flushes all matching waitid requests.
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);
