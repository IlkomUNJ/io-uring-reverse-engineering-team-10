// SPDX-License-Identifier: GPL-2.0

/* Close a fixed file descriptor (internal helper) */
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
		     unsigned int offset);

/* Prepare openat request - validate and set up open parameters */
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute openat operation */
int io_openat(struct io_kiocb *req, unsigned int issue_flags);
/* Clean up resources after openat operation */
void io_open_cleanup(struct io_kiocb *req);

/* Prepare openat2 request with extended attributes */
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute openat2 operation with resolve flags */
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare close request - validate file descriptor */
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Execute close operation */
int io_close(struct io_kiocb *req, unsigned int issue_flags);

/* Prepare to install fixed file descriptor */
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* Install file as fixed descriptor in io_uring */
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);
