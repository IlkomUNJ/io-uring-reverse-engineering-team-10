// SPDX-License-Identifier: GPL-2.0

// Sets up a tee operation, which duplicates data between pipes without consuming it.
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Performs the tee operation, duplicating the data inside the pipe buffer.
int io_tee(struct io_kiocb *req, unsigned int issue_flags);

// Cleans up after a splice operation, releasing any temporary state or resources.
void io_splice_cleanup(struct io_kiocb *req);
// Prepares a full splice operation from a submission queue entry (SQE).
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the actual splice system call, moving data between file descriptors.
int io_splice(struct io_kiocb *req, unsigned int issue_flags);
