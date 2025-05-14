// SPDX-License-Identifier: GPL-2.0

/* Sync message ring with given SQE */
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);
/* Prepare message ring request */
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute message ring operation */
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);
/* Cleanup message ring resources */
void io_msg_ring_cleanup(struct io_kiocb *req);
