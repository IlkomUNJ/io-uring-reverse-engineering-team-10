# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Libary | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | linux/mm/slub.c | kfree | 1
advise.c | linux/kernel.h | READ_ONCE | 5
| | linux/errno.h | EINVAL, EOPNOTSUPP | 2, 2
| | linux/fs.h | vfs_fadvise | 1
| | linux/file.h | req_set_fail | 1
| | linux/mm.h | do_madvise | 1
| | io_uring.h | io_kiocb_to_cmd | 4
| |  | io_req_set_res | 2 
| |  | IO_URING_F_NONBLOCK | 2
| |  | REQ_F_FORCE_ASYNC | 2 
| |  | IOU_OK	 | 2 
| | advise.c | io_madvise_prep | 1
| |  | io_madvise | 1
| |  | io_fadvise_force_async | 2
| |  | io_fadvise_prep | 1
| |  | io_fadvise | 1
| | uapi/linux/fadvise.h | POSIX_FADV_NORMAL | 1
| |  | POSIX_FADV_RANDOM | 1
| |  | POSIX_FADV_SEQUENTIAL | 1
advise.h | (none) | io_madvise_prep | 1
| |  | io_madvise | 1
| |  | io_fadvise_prep | 1
| |  | io_fadvise | 1
alloc_cache.c | alloc_cache.h | io_alloc_cache_get | 1
| | linux/mm.h | kvfree | 1
| |  | kvmalloc_array | 1
| | linux/slab.h | kmalloc | 1
| | linux/string.h | memset | 1
| | alloc_cache.h | io_alloc_cache_free | 1
| |  | io_alloc_cache_init | 1
| |  | io_cache_alloc_new | 1
cancel.c | linux/kernel.h | WARN_ON_ONCE | 1
| |  | READ_ONCE | 4
| |  | unlikely | 1
| | linux/errno.h | EINVAL, ENOENT, EALREADY, EBADF | 5, 6, 3, 3
| |  | ETIME | 1
| | linux/fs.h | fget, fput | 1, 1
| | linux/file.h | req_set_fail | 1 
| | uapi/linux/io_uring.h | IORING_* flags | 12
| | linux/ktime.h | ktime_get_ns | 1
| |  | ktime_add_ns | 1
| |  | KTIME_MAX | 1
| | linux/time.h | timespec64_to_ktime | 1
| | linux/sched.h | prepare_to_wait | 1
| |  | finish_wait | 1
| |  | schedule_hrtimeout | 1
| |  | TASK_INTERRUPTIBLE | 1
| | linux/hrtimer.h | HRTIMER_MODE_ABS | 1
| | linux/mutex.h | mutex_lock/unlock | 2, 2
| | io_uring.h | io_kiocb_to_cmd | 2
| |  | io_req_set_res | 1
| |  | io_file_get_fixed | 1
| |  | io_file_get_normal | 1
| |  | io_ring_submit_lock/unlock | 2, 2
| |  | io_run_task_work_sig | 1
| |  | io_match_task_safe | 1
| | poll.h | io_poll_cancel | 1
| | timeout.h | io_timeout_cancel | 1
| | waitid.h | io_waitid_cancel | 1
| | futex.h | io_futex_cancel | 1
| | cancel.c | io_cancel_req_match | 3
| |  | io_cancel_cb | 1
| |  | io_async_cancel_one | 3
| |  | io_try_cancel | 2
| |  | io_async_cancel_prep | 1
| |  | __io_async_cancel | 2
| |  | io_async_cancel | 1
| |  | __io_sync_cancel | 2
| |  | io_sync_cancel | 1
| |  | io_cancel_remove_all | 1
| |  | io_cancel_remove | 1
cancel.h | cancel.h	| io_cancel_match_sequence | 1
epoll.c	| linux/kernel.h | READ_ONCE | 4
| | linux/errno.h | EINVAL, EFAULT, EAGAIN | 3, 1, 2
| | linux/file.h | req_set_fail | 2
| | linux/uaccess.h | copy_from_user | 1
| |  | u64_to_user_ptr | 2
| | linux/eventpoll.h | do_epoll_ctl | 1
| |  | epoll_sendevents | 1
| | uapi/linux/io_uring.h | IO_URING_F_NONBLOCK | 1
| | io_uring.h | io_kiocb_to_cmd | 3
| |  | io_req_set_res | 2
| |  | IOU_OK | 2
| | epoll.c | io_epoll_ctl_prep | 1
| |  | io_epoll_ctl | 1
| |  | io_epoll_wait_prep | 1
| |  | io_epoll_wait | 1
| |  | ep_op_has_event | 1
eventfd.c | linux/kernel.h | READ_ONCE | 1
| |  | IS_ERR | 1
| |  | PTR_ERR | 1
| | linux/errno.h | EBUSY, EFAULT, ENOMEM, ENXIO | 1,1,1,1
| | linux/slab.h | kmalloc | 1
| |  | kfree | 2
| | linux/eventfd.h | eventfd_ctx_fdget | 1
| |  | eventfd_signal_mask | 2
| |  | eventfd_signal_allowed | 1
| |  | eventfd_ctx_put | 1
| | linux/eventpoll.h | EPOLL_URING_WAKE | 1
| | linux/io_uring_types.h | IORING_CQ_EVENTFD_DISABLED | 1
| | linux/refcount.h | refcount_dec_and_test | 1
| |  | refcount_inc_not_zero | 1
| |  | refcount_set | 1
| | linux/rcupdate.h | rcu_read_lock | 2
| |  | rcu_read_unlock | 2
| |  | call_rcu | 1
| |  | call_rcu_hurry | 1
| |  | rcu_dereference | 1
| |  | rcu_dereference_protected | 2
| |  | rcu_assign_pointer | 2
| | linux/atomic.h | atomic_fetch_or | 1
| |  | atomic_set | 1
| | linux/bitops.h | BIT | 1
| | linux/spinlock.h | spin_lock | 2
| |  | spin_unlock | 2
| | linux/uaccess.h | copy_from_user | 1
| | io-wq.h | io_wq_current_is_worker | 1
| | eventfd.c | io_eventfd_free | 1
| |  | io_eventfd_put | 3
| |  | io_eventfd_do_signal | 1
| |  | io_eventfd_release | 3
| |  | __io_eventfd_signal | 3
| |  | io_eventfd_trigger | 1
| |  | io_eventfd_grab | 2
| |  | io_eventfd_signal | 1
| |  | io_eventfd_flush_signal | 1
| |  | io_eventfd_register | 1
| |  | io_eventfd_unregister | 1
fdinfo.c | linux/kernel.h | READ_ONCE | 5
| |  | min | 2
| | linux/seq_file.h | seq_printf | 32
| |  | seq_puts | 9
| |  | seq_put_decimal_ull | 8
| |  | seq_put_hex_ll | 1
| |  | seq_putc | 1
| |  | seq_user_ns | 1
| |  | seq_file_path | 1
| | uapi/linux/io_uring.h | IORING_SETUP_* flags | 4
| | linux/user_namespace.h | from_kuid_munged | 4
| |  | from_kgid_munged | 5
| | linux/sched.h | getrusage | 1
| |  | RUSAGE_SELF | 1
| | linux/mutex.h | mutex_trylock | 1
| |  | mutex_unlock | 1
| | linux/spinlock.h | spin_lock | 1
| |  | spin_unlock | 1
| | linux/xarray.h | xa_empty | 1
| |  | xa_for_each | 1
| | io_uring.h | io_uring_get_opcode | 1
| | fdinfo.c | io_uring_show_cred | 1
| |  | common_tracking_show_fdinfo | 2
| |  | napi_show_fdinfo | 1
| |  | io_uring_show_fdinfo | 1
fileteble.c | linux/kernel.h | unlikely | 3
| | linux/errno.h | ENFILE, EBADF, ENXIO, EINVAL | 2,2,3,3
| |  | ENOMEM, EOVERFLOW | 1, 1
| | linux/file.h | fput	| 1
| |  | io_is_uring_fops | 1
| | linux/io_uring.h | IORING_FILE_INDEX_ALLOC	| 1
| |  | IORING_RSRC_FILE | 1
| | linux/overflow.h | check_add_overflow	| 1
| | io_uring.h | io_ring_submit_lock | 1
| |  | io_ring_submit_unlock | 1
| | rsrc.h | io_rsrc_data_alloc	 | 1
| |  | io_rsrc_data_free | 2
| |  | io_rsrc_node_alloc | 1
| |  | io_rsrc_node_lookup | 1
| |  | io_reset_rsrc_node | 2
| |  | io_fixed_file_set | 1
| | filetable.h | io_file_bitmap_set | 1
| |  | io_file_bitmap_clear | 1
| |  | io_file_table_set_alloc_range | 1
| | filetable.c | io_file_bitmap_get | 2
| |  | io_alloc_file_tables | 1
| |  | io_free_file_tables | 1
| |  | io_install_fixed_file | 1
| |  | __io_fixed_fd_install | 1
| |  | io_fixed_fd_install | 1
| |  | io_fixed_fd_remove | 1
| |  | io_register_file_alloc_range | 1
fileteble.h | linux/bitmap.h | test_bit | 1
| |  | __clear_bit | 1
| |  | __set_bit | 1
| | linux/compiler.h | WARN_ON_ONCE | 2
| | rsrc.h | REQ_F_SUPPORT_NOWAIT_BIT | 1
| | filetable.h | io_file_bitmap_clear | 1
| |  | io_file_bitmap_set | 1
| |  | io_slot_flags | 1
| |  | io_slot_file | 1
| |  | io_fixed_file_set | 1
| |  | io_file_table_set_alloc_range | 1
fs.c | linux/kernel.h | READ_ONCE | 19
| |  | WARN_ON_ONCE | 5
| |  | unlikely | 5
| | linux/errno.h | EINVAL | 8
| |  | EBADF | 5
| | linux/fs.h | do_renameat2 | 1
| |  | do_rmdir | 1
| |  | do_unlinkat	 | 1
| |  | do_mkdirat | 1
| |  | do_symlinkat | 1
| |  | do_linkat | 1
| | linux/namei.h | getname | 7
| |  | getname_uflags | 1
| |  | putname | 7
| | uapi/linux/io_uring.h | AT_REMOVEDIR | 1
| |  | REQ_F_* flags | 12
| | io_uring.h | io_kiocb_to_cmd | 10
| |  | io_req_set_res | 5
| |  | IOU_OK | 5
| | fs.c | io_renameat_prep | 1
| |  | io_renameat | 1
| |  | io_renameat_cleanup | 1
| |  | io_unlinkat_prep | 1
| |  | io_unlinkat | 1
| |  | io_unlinkat_cleanup | 1
| |  | io_mkdirat_prep | 1
| |  | io_mkdirat_cleanup | 1
| |  | io_mkdirat_prep | 1
| |  | io_symlinkat_prep | 1
| |  | io_symlinkat | 1
| |  | io_linkat_prep | 1
| |  | io_linkat | 1
| |  | io_link_cleanup	 | 1
futex.c | linux/kernel.h | READ_ONCE | 4
| |  | WARN_ON_ONCE | 1
| |  | unlikely | 4
| |  | __set_current_state | 1
| |  | TASK_RUNNING	 | 1
| | linux/errno.h | EINVAL, ENOMEM, ECANCELED | 5, 2, 1
| | uapi/linux/io_uring.h | IORING_OP_FUTEX_WAIT | 1
| |  | IOU_OK, IOU_ISSUE_SKIP_COMPLETE | 3, 2
| | kernel/futex/futex.h | futex_q_init | 1
| |  | futex_wake | 1
| |  | futex_unqueue | 1
| |  | futex_queue | 1
| |  | futex_wait_setup | 1
| |  | futex_parse_waitv | 1
| |  | futex_wait_multiple_setup | 1
| |  | futex_unqueue_multiple | 1
| |  | futex_flags_valid | 1
| |  | futex_validate_input | 2
| |  | futex2_to_flags | 1
| |  | FLAGS_STRICT | 1
| |  | FUTEX_WAITV_MAX | 1
| | io_uring.h | io_kiocb_to_cmd | 6
| |  | io_req_set_res | 7
| |  | io_req_task_work_add | 3
| |  | io_req_task_complete | 1
| |  | io_tw_lock | 2
| |  | req_set_fail | 3
| |  | hlist_add_head | 2
| |  | hlist_del_init | 3
| | alloc_cache.h | io_alloc_cache_init | 1
| |  | io_alloc_cache_free | 1
| |  | io_cache_free | 1
| |  | io_cache_alloc | 1
| | cancel.h | io_cancel_remove | 1
| |  | io_cancel_remove_all | 1
| | futex.c | io_futex_cache_init | 1
| |  | io_futex_cache_free | 1
| |  | __io_futex_complete | 2
| |  | io_futex_complete | 1
| |  | io_futexv_complete | 2
| |  | io_futexv_claim | 3
| |  | __io_futex_cancel | 1
| |  | io_futex_cancel | 1
| |  | io_futex_remove_all | 1
| |  | io_futex_prep | 1
| |  | io_futex_wakev_fn | 1
| |  | io_futexv_prep | 1
| |  | io_futex_wake_fn | 1
| |  | io_futexv_wait | 1
| |  | io_futex_wait | 1
| |  | io_futex_wake | 1
io_uring.c | /include/linux/kernel.h | BUILD_BUG_ON | 3
| |  | BUILD_BUG_ON_MSG | 1
| | /include/linux/slab.h | kmalloc | 5
| |  | kfree | 4
| | /include/linux/spin.h | spin_lock | 3
| |  | spin_unlock | 3
| | /include/linux/rcupdate.h | rcu_read_lock | 2
| |  | rcu_read_unlock | 2
| | /include/linux/rculist.h | list_add_tail_rcu | 1
| |  | list_del_rcu | 1
| | /include/linux/errno.h | ENOMEM | 2
| |  | EINVAL | 3
| |  | EFAULT | 2
| |  | EAGAIN | 1
| |  | ECANCELED | 1
| |  | EINTR | 1
| |  | EPERM | 1
| |  | EOPNOTSUPP | 1
| |  | EBADF | 1
| |  | EOVERFLOW | 1
| |  | EEXIST | 1
| |  | EOWNERDEAD | 1
| |  | ETIME | 1
| |  | EACCES | 1
| |  | EBADR | 1
| | /include/linux/ktime.h | ktime_get_ns | 1
| |  | ktime_add_ns | 1
| |  | KTIME_MAX | 1
| | /include/linux/time.h | timespec64_to_ktime | 1
| | /include/linux/sched.h | prepare_to_wait | 1
| |  | finish_wait | 1
| |  | schedule_hrtimeout | 1
| |  | TASK_INTERRUPTIBLE | 1
| | /include/linux/hrtimer.h | HRTIMER_MODE_ABS | 1
| | /include/linux/mutex.h | mutex_lock | 2
| |  | mutex_unlock | 2
| | /include/linux/uaccess.h | copy_from_user | 1
| |  | copy_to_user | 1
| | /include/linux/atomic.h | atomic_inc | 1
| |  | atomic_dec | 1
| |  | atomic_read | 1
| |  | atomic_set | 1
| | /include/linux/bitmap.h | bitmap_zero | 1
| |  | bitmap_fill | 1
| |  | bitmap_copy | 1
| |  | bitmap_and | 1
| |  | bitmap_or | 1
io_uring.h | linux/errno.h | EIOCBQUEUED | 1
| |  | EAGAIN | 1
| | linux/kasan.h | kasan_mempoel_umpoison_object | 1
| | linux/poll.h | EPOLLIN | 2
| |  | EPOLL_URING_WAKE | 2
| | linux/io_uring_types.h | io_uring_cqe | 1
| |  | io_uring_sqe | 1
| | uapi/linux/eventpoll.h | poll_to_key | 2
| | alloc_cache.h | io_cache_alloc | 1
| | io-wq.h | io_wq_work | 1
| |  | io_wq_free_work | 1
| |  | io_wq_submit_work | 1
| | slist.h | wq_list_add_tail | 1
| |  | wq_stack_extract | 1
| | filetable.h | fput | 1
| | opdef.h | io_issue_defs | 1
| | linux/lockdep.h | lockdep_assert | 4
| |  | lockdep_assert_held | 3
| | linux/resume_user_mode.h | resume_user_mode_work | 1
| | linux/slab.h | kmalloc | 1
| |  | kfree | 1
| | linux/trace_events.h | trace_io_uring_complete_enabled	 | 1
| |  | trace_io_uring_complete | 1
| | linux/wait.h | __wake_up	 | 1
| |  | wq_has_sleeper | 1
| | linux/sched.h | __set_current_state	 | 2
| |  | current | 6
| |  | test_thread_flag | 2
| |  | clear_notify_signal | 1
| |  | task_work_pending | 2
| |  | task_work_run | 1
| | linux/llist.h | llist_empty	 | 2
| | linux/kernel.h | READ_ONCE	 | 3
| |  | WRITE_ONCE | 1
| |  | smp_store_release | 1
| |  | smp_load_acquire | 1
| |  | min | 1
| |  | unlikely | 5
| |  | likely | 3
| |  | WARN_ON_ONCE | 1
| | linux/time.h | ktime_get | 1
| |  | ktime_get_with_offset | 1
| | linux/bitops.h | test_bit | 1
| | io_uring.c | io_should_wake | 1
| |  | io_cqe_cache_refill | 2
| |  | io_run_task_work_sig | 1
| |  | io_req_defer_failed | 1
| |  | io_post_aux_cqe | 1
| |  | io_add_aux_cqe | 1
| |  | io_req_post_cqe | 1
| |  | __io_commit_cqring_flush | 2
| |  | io_file_get_normal | 1
| |  | io_file_get_fixed | 1
| |  | __io_req_task_work_add | 2
| |  | io_req_task_work_add_remote | 1
| |  | io_req_task_queue | 1
| |  | io_req_task_complete | 2
| |  | io_req_task_queue_fail | 1
| |  | io_req_task_submit | 1
| |  | io_handle_tw_list | 1
| |  | tctx_task_work_run | 1
| |  | tctx_task_work | 1
| |  | io_uring_cancel_generic | 1
| |  | io_uring_alloc_task_context | 1
| |  | io_ring_add_registered_file | 2
| |  | io_req_queue_iowq | 1
| |  | io_poll_issue | 1
| |  | io_submit_sqes | 1
| |  | io_do_iopoll | 1
| |  | __io_submit_flush_completions | 2
| |  | io_free_req | 1
| |  | io_queue_next | 1
| |  | io_task_refs_refill | 2
| |  | __io_alloc_req_refill | 2
| |  | io_match_task_safe | 1
| |  | io_activate_pollwq | 1
| |  | io_is_compat | 1
| |  | io_req_task_work_add | 1
| |  | io_submit_flush_completions | 1
| |  | io_get_cqe_overflow | 2
| |  | io_get_cqe | 2
| |  | io_defer_get_uncommited_cqe | 1
| |  | io_fill_cqe_req | 1
| |  | req_set_fail | 1
| |  | io_req_set_res | 2
| |  | io_uring_alloc_async_data | 1
| |  | req_has_async_data | 1
| |  | io_put_file | 1
| |  | io_ring_submit_unlock | 1
| |  | io_ring_submit_lock | 1
| |  | io_commit_cqring | 1
| |  | io_poll_wq_wake | 1
| |  | io_cqring_wake | 1
| |  | io_sqring_full | 1
| |  | io_sqring_entries | 1
| |  | io_run_task_work | 1
| |  | io_local_work_pending | 2
| |  | io_task_work_pending	 | 1
| |  | io_tw_lock | 1
| |  | io_req_complete_defer | 1
| |  | io_commit_cqring_flush | 1
| |  | io_get_task_refs | 1
| |  | io_req_cache_empty | 1
| |  | io_extract_req | 1
| |  | io_alloc_req | 1
| |  | io_allowed_defer_tw_run | 1
| |  | io_allowed_run_tw | 1
| |  | io_should_terminate_tw | 1
| |  | io_req_queue_tw_complete | 1
| |  | uring_sqe_size | 1
| |  | io_file_can_poll	 | 1
| |  | io_get_time | 1
| |  | io_has_work | 1
io-wq.c | linux/kernel.h | WARN_ON_ONCE | 2
| |  | pr_warn_once | 1
| |  | atomic_read | 5
| |  | atomic_inc | 4
| |  | atomic_dec | 3
| |  | atomic_or | 3
| |  | atomic_set | 2
| |  | refcount_inc_not_zero | 1
| |  | refcount_dec_and_test | 2
| |  | refcount_set | 1
| | linux/sched.h | __set_current_state | 3
| |  | set_current_state | 2
| |  | wake_up_process | 2
| |  | task_work_add | 1
| |  | task_work_cancel_match | 2
| |  | task_work_run | 1
| |  | set_task_comm | 1
| | linux/slab.h | kzalloc | 1
| |  | kfree | 2
| |  | kfree_rcu | 1
| | linux/completion.h | init_completion | 2
| |  | wait_for_completion | 2
| |  | complete | 2
| | linux/rcupdate.h | rcu_read_lock | 4
| |  | rcu_read_unlock | 4
| | linux/cpumask.h | cpumask_set_cpu | 1
| |  | cpumask_test_cpu | 1
| |  | wake_up_process | 1
| |  | cpumask_subset | 1
| |  | cpumask_copy | 2
| | linux/cpuset.h | cpuset_cpus_allowed | 2
| | linux/sched/signal.h | fatal_signal_pending | 1
| |  | signal_pending | 1
| |  | get_signal | 1
| |  | __set_notify_signal | 2
| | linux/wait.h | __add_wait_queue | 1
| |  | wake_up | 2
| |  | wq_has_sleeper | 2
| | linux/timer.h | schedule_timeout | 1
| | linux/workqueue.h | INIT_DELAYED_WORK | 1
| |  | schedule_delayed_work | 1
| | linux/cpu.h | cpuhp_state_add_instance_nocalls	 | 1
| |  | cpuhp_state_remove_instance_nocalls | 1
| | linux/errno.h | EAGAIN | 1
| |  | ERESTARTSYS | 1
| |  | ERESTARTNOINTR | 1
| |  | ERESTARTNOHAND | 1
| | linux/hash.h | hash_ptr | 1
| | io-wq.h | io_wq_work | 1
| |  | io_wq_work_list | 1
| |  | io_wq_acct | 1
| |  | io_wq_hash | 1
| |  | io_wq_data | 1
| | io_uring.h | io_uring_task | 1
| | io-wq.c | create_io_worker | 2
| |  | io_wq_dec_running | 3
| |  | io_acct_cancel_pending_work | 3
| |  | create_worker_cb | 2
| |  | io_wq_cancel_tw_create | 2
| |  | io_worker_get | 3
| |  | io_worker_release | 6
| |  | io_get_acct | 3
| |  | io_work_get_acct | 2
| |  | io_wq_get_acct | 4
| |  | io_worker_ref_put | 5
| |  | io_wq_worker_stopped | 1
| |  | io_worker_cancel_cb | 1
| |  | io_task_worker_match | 1
| |  | io_worker_exit | 1
| |  | __io_acct_run_queue | 1
| |  | io_acct_run_queue | 3
| |  | io_acct_activate_free_worker | 2
| |  | io_wq_create_worker | 2
| |  | io_wq_inc_running | 2
| |  | io_queue_worker_create | 2
| |  | __io_worker_busy | 1
| |  | __io_worker_idle | 2
| |  | __io_get_work_hash | 3
| |  | io_get_work_hash | 2
| |  | io_wait_on_hash | 1
| |  | io_get_next_work | 1
| |  | io_assign_current_work | 3
| |  | io_worker_handle_work | 2
| |  | io_wq_worker | 1
| |  | io_wq_worker_running | 1
| |  | io_wq_worker_sleeping | 1
| |  | io_init_new_worker | 2
| |  | io_wq_work_match_all | 1
| |  | io_should_retry_thread | 1
| |  | queue_create_worker_retry | 1
| |  | create_worker_cont | 1
| |  | io_workqueue_create | 1
| |  | io_acct_for_each_worker | 3
| |  | io_wq_for_each_worker | 3
| |  | io_wq_worker_wake | 2
| |  | io_run_cancel | 3
| |  | io_wq_insert_work | 1
| |  | io_wq_work_match_item | 1
| |  | io_wq_enqueue | 1
| |  | io_wq_hash_work | 1
| |  | __io_wq_worker_cancel | 1
| |  | io_wq_worker_cancel | 1
| |  | io_wq_remove_pending | 1
| |  | io_wq_cancel_pending_work | 2
| |  | io_acct_cancel_running_work | 1
| |  | io_wq_cancel_running_work | 1
| |  | io_wq_cancel_cb | 1  
| |  | io_wq_hash_wake | 1
| |  | io_wq_create | 1
| |  | io_task_work_match | 1
| |  | io_wq_exit_start | 1
| |  | io_wq_exit_workers | 1
| |  | io_wq_destroy | 1
| |  | io_wq_put_and_exit | 1
| |  | io_wq_worker_affinity | 1
| |  | __io_wq_cpu_online | 2
| |  | io_wq_cpu_online | 1
| |  | io_wq_cpu_offline | 1
| |  | io_wq_cpu_affinity | 1
| |  | io_wq_max_workers | 1
| |  | io_wq_init | 1
io-wq.h | linux/refcount.h | refcount_dec_and_test | 1
| |  | pr_warn_once | 1
| | linux/io_uring_types.h | io_uring_task | 1
| | linux/sched.h | in_task | 1
| |  | current | 2
| |  | current | 4
| | linux/wait.h | wait_queue_head | 1
| | io-wq.h | io_wq_work | 1
| |  | io_wq_work_list | 1
| |  | io_wq_acct | 1
| |  | io_wq_hash | 1
| |  | io_wq_data | 1
| | io_uring.h | io_uring_task | 1
| | io-wq.h | io_wq_put_hash | 1
| |  | __io_wq_is_hashed | 2
| |  | io_wq_is_hashed | 1
| |  | io_wq_current_is_worker | 1
| |  | io_wq_create | 1
| |  | io_wq_exit_start | 1
| |  | io_wq_put_and_exit | 1
| |  | io_wq_enqueue | 1
| |  | io_wq_hash_work | 1
| |  | io_wq_cpu_affinity | 1
| |  | io_wq_max_workers | 1
| |  | io_wq_worker_stopped | 1
| |  | io_wq_cancel_cb | 1
| |  | io_wq_worker_sleeping | 2
| |  | io_wq_worker_running | 2
kbuf.c | linux/kernel.h | WARN_ON_ONCE | 2
| |  | min_t | 2
| |  | min_not_zero | 1
| |  | READ_ONCE | 5
| |  | WRITE_ONCE | 1
| |  | smp_load_acquire | 2
| |  | check_mul_overflow | 1
| |  | check_add_overflow | 1
| | linux/errno.h | EINVAL | 7
| |  | ENOENT | 3
| |  | ENOMEM | 3
| |  | EOVERFLOW | 1
| |  | E2BIG | 2
| |  | EEXIST | 1
| |  | EFAULT | 1
| |  | EAGAIN | 1
| | linux/slab.h | kzalloc | 2
| |  | kmalloc | 2
| |  | kmalloc_array | 1
| |  | kfree | 4
| | linux/uaccess.h | access_ok | 1
| |  | copy_from_user | 3
| |  | copy_to_user | 1
| | linux/io_uring.h | IOU_OK | 2
| |  | IORING_CQE_F_BUFFER | 1
| |  | IORING_CQE_F_BUF_MORE | 1
| |  | IORING_OFF_PBUF_SHIFT | 1
| |  | IORING_MEM_REGION_TYPE_USER | 1
| | linux/mm.h | PAGE_ALIGN | 1
| | linux/fs.h | cond_resched | 3
| | io_uring.h | io_kiocb_to_cmd | 3
| | io_uring_types.h | io_uring_buf_reg | 1
| |  | io_uring_buf_status | 1
| |  | io_uring_region_desc | 1
| | kbuf.h | io_ring_head_to_buf | 6
| | memmap.h | io_create_region_mmap_safe | 1
| |  | io_free_region | 3
| |  | io_region_get_ptr | 1
| | kbuf.c | io_kbuf_inc_commit | 2
| |  | io_kbuf_commit | 5
| |  | io_buffer_get_list | 10
| |  | io_buffer_add_list | 3
| |  | io_kbuf_drop_legacy | 2
| |  | io_kbuf_recycle_legacy | 1
| |  | io_provided_buffer_select | 3
| |  | io_provided_buffers_select | 3
| |  | io_ring_buffer_select | 1
| |  | io_buffer_select | 1
| |  | io_ring_buffers_peek | 3
| |  | io_buffers_select | 1
| |  | io_buffers_peek | 1
| |  | __io_put_kbuf_ring | 2
| |  | __io_put_kbufs | 1
| |  | __io_remove_buffers | 4
| |  | io_put_bl | 3
| |  | io_destroy_buffers | 1
| |  | io_destroy_bl | 2
| |  | io_remove_buffers_prep | 1
| |  | io_remove_buffers | q
| |  | io_provide_buffers_prep | 1
| |  | io_add_buffers | 1
| |  | io_provide_buffers | 1
| |  | io_register_pbuf_ring | 1
| |  | io_unregister_pbuf_ring | 1
| |  | io_register_pbuf_status | 1
| |  | io_pbuf_get_region | 1
kbuf.h | uapi/linux/io_uring.h | io_uring_sqe | 2
| | linux/io_uring_types.h | io_kiocb | 1
| |  | io_ring_ctx | 1
| |  | io_uring_buf_ring | 1
| | kbuf.h | io_buffer_select | 1
| |  | io_buffers_select | 1
| |  | io_buffers_peek | 1
| |  | io_destroy_buffers | 1
| |  | io_remove_buffers_prep | 1
| |  | io_remove_buffers | 1
| |  | io_provide_buffers_prep | 1
| |  | io_provide_buffers | 1
| |  | io_register_pbuf_ring | 1
| |  | io_unregister_pbuf_ring | 1
| |  | io_register_pbuf_status | 1
| |  | io_kbuf_recycle_legacy | 2
| |  | io_kbuf_drop_legacy | 1
| |  | __io_put_kbufs | 3
| |  | io_kbuf_commit | 1
| |  | io_pbuf_get_region | 1
| |  | io_kbuf_recycle_ring | 1
| |  | io_do_buffer_select | 1
| |  | io_kbuf_recycle | 1
| |  | io_put_kbuf | 1
| |  | io_put_kbufs | 1

















Continue with the list untill all functions used in each source are listed.