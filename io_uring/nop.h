// SPDX-License-Identifier: GPL-2.0

/* Prepare a no-operation request, just validates the SQE without doing any work */
int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute a no-operation request that immediately completes successfully */
int io_nop(struct io_kiocb *req, unsigned int issue_flags);
