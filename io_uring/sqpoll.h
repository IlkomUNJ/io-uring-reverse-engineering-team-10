// SPDX-License-Identifier: GPL-2.0

struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

	u64			work_time;
	unsigned long		state;
	struct completion	exited;
};

// Sets up and initializes SQPOLL offload mode based on user parameters.
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);
// Final cleanup routine run by the SQPOLL thread before it exits.
void io_sq_thread_finish(struct io_ring_ctx *ctx);
// Signals the SQPOLL thread to exit and stops polling activity.
void io_sq_thread_stop(struct io_sq_data *sqd);
// Parks (suspends) the SQPOLL thread to conserve CPU when idle.
void io_sq_thread_park(struct io_sq_data *sqd);
// Wakes up the SQPOLL kernel thread if it’s parked due to inactivity.
void io_sq_thread_unpark(struct io_sq_data *sqd);
// Decrements the reference count of the SQPOLL context and frees it if it hits zero.
void io_put_sq_data(struct io_sq_data *sqd);
// Waits until the SQPOLL thread is ready and can start accepting work
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);
// Applies CPU affinity settings for the SQPOLL thread based on user-provided configuration.
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);
