// SPDX-License-Identifier: GPL-2.0

//Prepares the madvise operation by extracting parameters from the submission queue entry (SQE).
int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Executes the madvise operation, which provides memory management advice for a memory range.
int io_madvise(struct io_kiocb *req, unsigned int issue_flags);

//Prepares the fadvise operation by extracting parameters from the submission queue entry (SQE).
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Executes the fadvise operation, which provides advice about file access patterns to the kernel.
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);
