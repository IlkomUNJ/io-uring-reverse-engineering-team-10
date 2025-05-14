// SPDX-License-Identifier: GPL-2.0

/** 
 * Prepare a truncate request for submission.
 * Validates the SQE and initializes truncate parameters.
 */
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/** 
 * Execute a truncate request.
 * Calls the kernel's truncate function and sets the result.
 */
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
