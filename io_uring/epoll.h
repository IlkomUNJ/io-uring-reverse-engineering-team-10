// SPDX-License-Identifier: GPL-2.0

#if defined(CONFIG_EPOLL)
//Prepares the epoll_ctl operation by extracting parameters from the submission queue entry (SQE).
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Executes the epoll_ctl operation, which modifies the interest list of an epoll instance.
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);
//Prepares the epoll_wait operation by extracting parameters from the SQE, including the maximum number of events and the user-space event buffer.
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Executes the epoll_wait operation, which retrieves events from the epoll instance and sends them to the user-space buffer.
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);
#endif
