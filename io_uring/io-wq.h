#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq;

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	/* cancelled before started */
	IO_WQ_CANCEL_RUNNING,	/* found, running, and attempted cancelled */
	IO_WQ_CANCEL_NOTFOUND,	/* work not found */
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
typedef void (io_wq_work_fn)(struct io_wq_work *);

struct io_wq_hash {
	refcount_t refs;
	unsigned long map;
	struct wait_queue_head wait;
};

static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))
		kfree(hash);
}

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);
// Stops new task submissions and prepares worker threads for termination.
void io_wq_exit_start(struct io_wq *wq);
// Decrements the reference count of an io-wq and, if it reaches zero, begins the exit process.
void io_wq_put_and_exit(struct io_wq *wq);

// Ensures the task is queued properly and may trigger worker activation if necessary.
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
// Used to manage and categorize tasks efficiently in the work queue.
void io_wq_hash_work(struct io_wq_work *work, void *val);

// Ensures that workers in the queue operate on specific CPUs, optimizing resource allocation.
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
// Retrieves the maximum number of workers allowed for the work queue.
int io_wq_max_workers(struct io_wq *wq, int *new_count);
// Checks if a worker thread has stopped running.
bool io_wq_worker_stopped(void);

// private function to check if a task is already hashed in the queue.
static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;
}

// Public function to check if a work item is hashed.
static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)
extern void io_wq_worker_sleeping(struct task_struct *);
extern void io_wq_worker_running(struct task_struct *);
#else
// Checks if a worker thread is currently sleeping (waiting for work).
static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
// Checks if a worker thread is actively processing a task.
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

// Determines if the current thread is a worker thread in the io-wq.
static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&
		current->worker_private;
}
#endif
