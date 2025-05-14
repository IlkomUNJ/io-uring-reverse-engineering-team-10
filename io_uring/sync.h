// SPDX-License-Identifier: GPL-2.0

// Prepares a sync_file_range() request from an SQE.
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the sync_file_range() system call to flush a specific file range from the page cache to disk.
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

// Prepares a fsync() or fdatasync() operation.
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the fsync() or fdatasync() syscall to flush changes to disk, ensuring persistence.
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

// Executes the fallocate() syscall, allocating space on disk without writing actual data.
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);
// Prepares a fallocate() request to preallocate disk space for a file.
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
