// SPDX-License-Identifier: GPL-2.0

/** 
 * Structure to hold timeout data for a request.
 * Includes timer, timespec, mode, and flags.
 */
struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
	u32				flags;
};

/** 
 * Disarm a linked timeout request and remove it from the list.
 * Cancels the timer and unlinks the timeout from the request.
 */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

/** 
 * Inline function to disarm a linked timeout request.
 * Checks if the linked request is a timeout and disarms it.
 */
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

/** 
 * Flush all timeouts in the context that have been satisfied.
 * Removes expired timeouts and updates the last flush sequence.
 */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);
struct io_cancel_data;
/** 
 * Cancel a timeout request in the context based on cancel data.
 * Completes the request with an error if found.
 */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);
/** 
 * Kill all timeouts in the context that match the given task.
 * Cancels and flushes the matching timeout requests.
 */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);
				 
/** 
 * Queue a linked timeout request for execution.
 * Starts the timer and adds the timeout to the linked timeout list.
 */
void io_queue_linked_timeout(struct io_kiocb *req);
/** 
 * Disarm the next linked timeout request for the given request.
 * Cancels the linked timeout and completes it with an error.
 */
void io_disarm_next(struct io_kiocb *req);

/** 
 * Prepare a timeout request for submission.
 * Validates the SQE and initializes timeout parameters.
 */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/** 
 * Prepare a linked timeout request for submission.
 * Validates the SQE and initializes timeout parameters for linked timeouts.
 */
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/** 
 * Submit a timeout request for execution.
 * Adds the timeout to the context's timeout list and starts the timer.
 */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);
/** 
 * Prepare a timeout removal request.
 * Validates the SQE and extracts timeout removal parameters.
 */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/** 
 * Remove or update an existing timeout command.
 * Handles both timeout removal and timeout update operations.
 */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);
