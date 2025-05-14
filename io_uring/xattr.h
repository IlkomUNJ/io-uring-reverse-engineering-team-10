// SPDX-License-Identifier: GPL-2.0

// Cleanup resources for xattr requests.
// Frees allocated memory and resets request state.
void io_xattr_cleanup(struct io_kiocb *req);

// Prepare a setxattr request for a file descriptor.
// Validates the SQE and initializes xattr parameters.

// Execute a setxattr request for a file descriptor.
// Calls the kernel's file_setxattr function and finalizes the request.
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepare a setxattr request for a file path.
// Validates the SQE and initializes xattr parameters for paths.
// Execute a setxattr request for a file path.
// Calls the kernel's filename_setxattr function and finalizes the request.
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepare a getxattr request for a file descriptor.
// Validates the SQE and initializes xattr parameters.
// Execute a getxattr request for a file descriptor.
// Calls the kernel's file_getxattr function and finalizes the request.
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepare a getxattr request for a file path.
// Validates the SQE and initializes xattr parameters for paths.
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Execute a getxattr request for a file path.
// Calls the kernel's filename_getxattr function and finalizes the request.
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
