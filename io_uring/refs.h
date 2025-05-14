#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define req_ref_zero_or_close_to_overflow(req)	\
	((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

// This macro checks if the request reference count is near zero or close to overflow.
static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	return atomic_inc_not_zero(&req->refs);
}

//This function increments the reference counter if it's not zero and warns if the request doesn't have the REQ_F_REFCOUNT flag.
static inline bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

//This function atomically decrements the reference counter and returns true if it becomes zero.
static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))
		return true;

	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	return atomic_dec_and_test(&req->refs);
}

//Decrements the reference counter and returns true if it's zero or doesn't have the REQ_F_REFCOUNT flag.
static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_inc(&req->refs);
}

//Increments the request reference counter and verifies that the request has the REQ_F_REFCOUNT flag.
static inline void req_ref_put(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));
	atomic_dec(&req->refs);
}

//Decrements the reference counter and ensures the request has the REQ_F_REFCOUNT flag.
static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {
		req->flags |= REQ_F_REFCOUNT;
		atomic_set(&req->refs, nr);
	}
}

//Sets the REQ_F_REFCOUNT flag and initializes the reference counter if not already set.
static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);
}
#endif
