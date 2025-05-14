// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

struct io_async_cmd {
	struct io_uring_cmd_data	data;
	struct iou_vec			vec;
	struct io_uring_sqe		sqes[2];
};

// Execute a uring command.
// Calls the file operation's uring_cmd handler.
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);
// Prepare a uring command for submission.
// Validates the SQE and initializes command parameters.
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Cleanup a uring command request.
// Frees async data and resets request state.
void io_uring_cmd_cleanup(struct io_kiocb *req);

// Try to cancel a uring command.
// Iterates through cancelable commands and attempts cancellation.
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

// Free the cached async command entry.
// Releases memory and associated resources for the command.
void io_cmd_cache_free(const void *entry);

// Import a fixed vector for a uring command.
// Prepares and maps the vector into the kernel.
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);
