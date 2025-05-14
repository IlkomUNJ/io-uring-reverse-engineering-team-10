// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>
#include <linux/pagemap.h>

struct io_meta_state {
	u32			seed;
	struct iov_iter_state	iter_meta;
};

struct io_async_rw {
	struct iou_vec			vec;
	size_t				bytes_done;

	struct_group(clear,
		struct iov_iter			iter;
		struct iov_iter_state		iter_state;
		struct iovec			fast_iov;
		/*
		 * wpq is for buffered io, while meta fields are used with
		 * direct io
		 */
		union {
			struct wait_page_queue		wpq;
			struct {
				struct uio_meta			meta;
				struct io_meta_state		meta_state;
			};
		};
	);
};

// Prepares a fixed read operation, meaning the I/O buffer is pre-allocated and cannot be changed during the operation.
int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a fixed write operation, where the buffer for writing is pre-allocated and fixed for the duration of the operation.
int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a fixed readv operation, which is a vectorized read using pre-allocated buffers.
int io_prep_readv_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a fixed writev operation, which is a vectorized write using pre-allocated buffers.
int io_prep_writev_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a vectorized read operation (readv), where multiple buffers are specified for reading, improving efficiency in some cases.
int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a writev operation (vectorized write) for execution.
int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a read operation for execution.
int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Prepares a write operation for execution.
int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Performs a read operation.
int io_read(struct io_kiocb *req, unsigned int issue_flags);
// Performs a write operation.
int io_write(struct io_kiocb *req, unsigned int issue_flags);
// Performs a fixed read operation.
int io_read_fixed(struct io_kiocb *req, unsigned int issue_flags);
// Performs a fixed write operation.
int io_write_fixed(struct io_kiocb *req, unsigned int issue_flags);
// Cleans up resources after a readv/writev operation.
void io_readv_writev_cleanup(struct io_kiocb *req);
// Marks a read/write operation as failed and handles any necessary cleanup.
void io_rw_fail(struct io_kiocb *req);
// Marks a read/write request as complete.
void io_req_rw_complete(struct io_kiocb *req, io_tw_token_t tw);
// Prepares a read operation with memory shot support.
int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//  Performs a read operation with memory shot support.
int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags);
// Frees cached resources used during read/write operations, ensuring proper memory management and preventing leaks
void io_rw_cache_free(const void *entry);
