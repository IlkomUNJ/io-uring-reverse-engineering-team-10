// SPDX-License-Identifier: GPL-2.0

// Prepares a statx request by extracting parameters from the submission queue entry (SQE) and validating them.
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the statx() system call to retrieve file information (timestamps, size, inode, etc.).
int io_statx(struct io_kiocb *req, unsigned int issue_flags);
// Cleans up any resources or state associated with the statx request.
void io_statx_cleanup(struct io_kiocb *req);
