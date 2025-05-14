// SPDX-License-Identifier: GPL-2.0
// Prepares the parameters and resources needed for a rename operation, ensuring the input is valid.
int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the actual renaming of a file or directory, moving it from one path to another.
int io_renameat(struct io_kiocb *req, unsigned int issue_flags);
// Cleans up resources and handles any post-operation tasks for the rename operation.
void io_renameat_cleanup(struct io_kiocb *req);

// Prepares for an unlink operation by validating inputs and setting up the necessary resources.
int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Performs the actual deletion of a file or directory.
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);
// Cleans up resources and finalizes the unlink operation.
void io_unlinkat_cleanup(struct io_kiocb *req);

// Prepares for creating a new directory by validating inputs and setting up resources.
int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the directory creation operation.
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);
// Finalizes the operation, releasing any resources used.
void io_mkdirat_cleanup(struct io_kiocb *req);

// Prepares the symbolic link operation by validating the source and target paths and initializing resources.
int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Creates a symbolic link pointing from one path to another.
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);

// Prepares the creation of a hard link, validating paths and setting up resources.
int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes the creation of a hard link to an existing file.
int io_linkat(struct io_kiocb *req, unsigned int issue_flags);
// Cleans up resources and performs any necessary finalization for the hard link operation.
void io_link_cleanup(struct io_kiocb *req);
