// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

/* Unregister and clean up an eventfd registration */
int io_eventfd_unregister(struct io_ring_ctx *ctx);
/* Remove a registered personality by ID */
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif
