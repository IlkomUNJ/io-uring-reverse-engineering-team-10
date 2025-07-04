// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};

//Prepares the asynchronous cancellation operation by extracting parameters from the submission queue entry (SQE).
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Executes the asynchronous cancellation of a request.
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

//Attempts to cancel a specific request based on the provided cancellation data.
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

//Performs a synchronous cancellation of a request using user-provided arguments.
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

//Removes and cancels a specific request from the list based on the cancellation criteria.
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

// Matches a request's cancellation sequence and updates it if necessary.
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif
