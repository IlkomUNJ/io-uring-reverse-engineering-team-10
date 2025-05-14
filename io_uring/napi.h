/* SPDX-License-Identifier: GPL-2.0 */

#ifndef IOU_NAPI_H
#define IOU_NAPI_H

#include <linux/kernel.h>
#include <linux/io_uring.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL

/* Initialize NAPI busy poll structures for this io_uring context */
void io_napi_init(struct io_ring_ctx *ctx);
/* Clean up all NAPI resources associated with this context */
void io_napi_free(struct io_ring_ctx *ctx);

/* Register NAPI busy poll with user-provided arguments */
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);
/* Unregister and disable NAPI busy poll for this context */
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);

/* Internal: Add NAPI ID to tracking list for busy polling */
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);

/* Core busy poll loop implementation for NAPI sockets */
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);
/* SQPOLL thread busy poll handler */
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

/* Check if any NAPI sockets are registered for busy poll */
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return !list_empty(&ctx->napi_list);
}

/* Conditionally execute busy poll loop if NAPI is active */
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
	if (!io_napi(ctx))
		return;
	__io_napi_busy_loop(ctx, iowq);
}

/* Track new socket's NAPI ID for dynamic busy polling */
static inline void io_napi_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct socket *sock;

	if (READ_ONCE(ctx->napi_track_mode) != IO_URING_NAPI_TRACKING_DYNAMIC)
		return;

	sock = sock_from_file(req->file);
	if (sock && sock->sk)
		__io_napi_add_id(ctx, READ_ONCE(sock->sk->sk_napi_id));
}

#else

/* Stubs when CONFIG_NET_RX_BUSY_POLL is disabled */
static inline void io_napi_init(struct io_ring_ctx *ctx)
{
}
static inline void io_napi_free(struct io_ring_ctx *ctx)
{
}
static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return false;
}
static inline void io_napi_add(struct io_kiocb *req)
{
}
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
}
static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

#endif
