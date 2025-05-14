// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

struct io_async_msghdr {
#if defined(CONFIG_NET)
	struct iou_vec				vec;

	struct_group(clear,
		int				namelen;
		struct iovec			fast_iov;
		__kernel_size_t			controllen;
		__kernel_size_t			payloadlen;
		struct sockaddr __user		*uaddr;
		struct msghdr			msg;
		struct sockaddr_storage		addr;
	);
#else
	struct_group(clear);
#endif
};

#if defined(CONFIG_NET)

/*
 * Prepare shutdown request from SQE, set up io_kiocb with shutdown parameters.
 */
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Execute socket shutdown operation, handling non-blocking mode based on issue_flags.
 */
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Clean up resources after sendmsg/recvmsg operations, release allocated buffers.
 */
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);

/*
 * Prepare sendmsg request, parse SQE and validate message parameters.
 */
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Execute sendmsg operation, handling both blocking and non-blocking modes.
 */
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Basic send operation, optimized for simple socket writes.
 */
int io_send(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Prepare recvmsg request, set up buffers and message headers from SQE.
 */
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Execute recvmsg operation, may return partial reads in non-blocking mode.
 */
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Basic recv operation, simplified version of recvmsg for common cases.
 */
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Handle failure cases for send/recv operations, set appropriate error codes.
 */
void io_sendrecv_fail(struct io_kiocb *req);

/*
 * Prepare socket accept request, validate parameters from SQE.
 */
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Execute accept operation, may defer in non-blocking mode.
 */
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Prepare socket creation request, parse domain/type/protocol from SQE.
 */
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Create new socket and register with io_uring instance.
 */
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Prepare socket connect request, set up address parameters.
 */
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Initiate connection, handles both blocking and non-blocking modes.
 */
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Execute zero-copy send, avoids data copying between kernel and userspace.
 */
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Zero-copy version of sendmsg, for vectored I/O with metadata.
 */
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Prepare zero-copy send request, validate buffers and setup registration.
 */
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Clean up resources after zero-copy send operation.
 */
void io_send_zc_cleanup(struct io_kiocb *req);

/*
 * Prepare socket bind request, parse address from SQE.
 */
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Bind socket to specified address, synchronous operation.
 */
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Prepare socket listen request, validate backlog parameter.
 */
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Start listening on bound socket, enables connection acceptance.
 */
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Free cached network resources when io_uring instance is torn down.
 */
void io_netmsg_cache_free(const void *entry);

#else
/* Network operations not supported in this configuration */
static inline void io_netmsg_cache_free(const void *entry) {}
#endif