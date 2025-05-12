# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Library | Function utilized | Time Used
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
memmap.c | linux/kernel.h | WARN_ON_ONCE | 4
| | linux/errno.h | ENOMEM, EINVAL, EFAULT, E2BIG, EOVERFLOW | 10+
| |	linux/mm.h | pin_user_pages_fast, unpin_user_pages, release_pages, vm_insert_pages | 5
| | linux/mman.h | VM_DONTEXPAND, MAP_SHARED | 2
| |	linux/slab.h | kvmalloc_array, kvfree | 3
| |	linux/vmalloc.h | vmap, vunmap | 2
| |	linux/io_uring.h | io_uring_region_desc, io_ring_ctx | 2
| | asm/shmparam.h | SHM_COLOUR | 1
| |	memmap.h | io_mapped_region, io_region_is_set, io_region_get_ptr | 5
| |	kbuf.h | io_check_coalesce_buffer | 1
| |	rsrc.h | __io_account_mem, __io_unaccount_mem | 2
| | memmap.c | io_mem_alloc_compound | 1
| | memmap.c | io_pin_pages | 2
| | memmap.c | io_free_region | 2 
| | memmap.c | io_region_init_ptr | 1 
| | memmap.c | io_region_pin_pages | 1 
| | memmap.c | io_region_allocate_pages | 1
| | memmap.c | io_create_region | 2
| | memmap.c | io_create_region_mmap_safe | 1
| | memmap.c | io_mmap_get_region | 2
| | memmap.c | io_region_validate_mmap | 2
| | memmap.c | io_uring_validate_mmap_request | 3
| | memmap.c | io_region_mmap | 1
| | memmap.c | io_uring_mmap | 2
| | memmap.c | io_uring_get_unmapped_area | 2
memmap.h | linux/fs.h | struct file | 3
| | memmap.h | io_pin_pages | 1 
| | memmap.h | io_uring_get_unmapped_area | 1
| | memmap.h | io_uring_mmap | 1
| | memmap.h | io_free_region | 1
| | memmap.h | io_create_region_mmap_safe | 1
| | memmap.h | io_region_get_ptr | 1
| | memmap.h | io_region_is_set | 1
| msg_ring.c | linux/kernel.h | WARN_ON_ONCE, READ_ONCE | 4 
| | linux/errno.h | EAGAIN, EINVAL, EBADFD, ENOMEM, EOVERFLOW, EOWNERDEAD | 10+
| | linux/file.h | fput, get_file | 2
| | tools/include/linux/slab.h | kmem_cache_alloc | 1
| | mm/slub.c | kmem_cache_free | 2
| | include/linux/gfp_types.h | __GFP_NOWARN | 1
| | include/linux/gfp_types.h | __GFP_ZERO | 1
| | io_uring.h | io_kiocb, io_ring_ctx | 10+ 
| | rsrc.h | io_rsrc_node_lookup | 1
| | filetable.h | io_slot_file | 1
| | filetable.h | __io_fixed_fd_install | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_alloc_cache_put | 1
| | msg_ring.c | io_double_unlock_ctx | 2
| | msg_ring.c | io_lock_external_ctx | 3
| | msg_ring.c | io_msg_ring_cleanup | 1
| | msg_ring.c | io_msg_need_remote | 2
| | msg_ring.c | io_msg_tw_complete | 1
| | msg_ring.c | io_msg_remote_post | 1
| | msg_ring.c | io_msg_get_kiocb | 1
| | msg_ring.c | io_msg_data_remote | 1
| | msg_ring.c | __io_msg_ring_data | 2
| | msg_ring.c | io_msg_ring_data | 1
| | msg_ring.c | io_msg_grab_file | 1
| | msg_ring.c | io_msg_install_complete | 2
| | msg_ring.c | io_msg_tw_fd_complete | 1
| | msg_ring.c | io_msg_fd_remote | 1
| | msg_ring.c | io_msg_send_fd	| 1
| | msg_ring.c | __io_msg_ring_prep | 2
| | msg_ring.c | io_msg_ring_prep | 1
| | msg_ring.c | io_msg_ring | 1
| | msg_ring.c | io_uring_sync_msg_ring | 1
| | msg_ring.h | io_uring_sync_msg_ring | 1
| | msg_ring.h | io_msg_ring_prep | 1
| | msg_ring.h | io_msg_ring | 1
| | msg_ring.h | io_msg_ring_cleanup | 1
| | include/uapi/linux/io_uring.h | io_uring_sqe  | 2
| | include/linux/io_uring_types.h | io_kiocb | 3
napi.c | io_uring.h | io_ring_ctx, io_wait_queue, io_should_wake, io_has_work | 10+ 
| | linux/kernel.h | WARN_ON_ONCE, READ_ONCE, WRITE_ONCE | 5 
| | include/linux/types.h | ktime_t | 8
| | include/linux/jiffies.h | time_after | 3
| | include/linux/rculist.h | INIT_LIST_HEAD | 2
| | include/linux/rculist.h | list_add_tail_rcu | 1
| | include/linux/rculist.h | list_del_rcu | 2
| | include/linux/rculist.h | list_for_each_entry_rcu | 2
| | include/linux/list.h | list_is_singular | 1
| | include/linux/rculist.h | hlist_for_each_entry_rcu | | 1
| | include/linux/rculist.h | hlist_add_tail_rcu | 1
| | include/linux/hashtable.h | hash_del_rcu | 3
| | tools/include/linux/slab.h | kmalloc | 1
| | mm/slub.c | kfree | 1
| | include/linux/rcupdate.h | kfree_rcu | 3
| | linux/errno.h | EINVAL, EEXIST, ENOMEM, ENOENT	5 
| | linux/spinlock.h | spin_lock | 1
| | linux/spinlock.h | spin_unlock | 2
| | linux/spinlock.h | spin_lock_init | 1
| | linux/ktime.h | ns_to_ktime | 2
| | linux/ktime.h | ktime_add | 1
| | linux/ktime.h | ktime_after | 1
| | linux/ktime.h | ktime_sub | 1
| | include/linux/sched/signal.h, | signal_pending | 1
| | include/net/busy_poll.h | napi_busy_loop_rcu | 1
| | include/net/busy_poll.h | busy_loop_current_time | 2
| | napi.c | io_napi_hash_find | 2
| | napi.c | __io_napi_add_id | 2
| | napi.c | __io_napi_del_id | 1
| | napi.c | __io_napi_remove_stale | 2
| | napi.c | io_napi_remove_stale | 2
| | napi.c | io_napi_busy_loop_timeout | 2
| | napi.c | io_napi_busy_loop_should_end | 2
| | napi.c | static_tracking_do_busy_loop | 1
| | napi.c | dynamic_tracking_do_busy_loop | 1
| | napi.c | __io_napi_do_busy_loop | 2
| | napi.c | io_napi_blocking_busy_loop | 1
| | napi.c | io_napi_init | 1
| | napi.c | io_napi_free | 1
| | napi.c | io_napi_register_napi | 1
| | napi.c | io_register_napi | 1
| | napi.c | io_unregister_napi | 1
| | napi.c | __io_napi_busy_loop | 1
| | napi.c | io_napi_sqpoll_busy_poll | 1
napi.h | linux/kernel.h | READ_ONCE | 2 
| | include/net/sock.h, | sk_napi_id | 1
| | linux/list.h | list_empty | 1
| | linux/errno.h | EOPNOTSUPP | 2 
| | napi.h | io_napi_init | 1
| | napi.h | io_napi_free | 1
| | napi.h | io_register_napi | 1
| | napi.h | io_unregister_napi | 1
| | napi.h | __io_napi_add_id | 1
| | napi.h | __io_napi_busy_loop | 1
| | napi.h | o_napi_sqpoll_busy_poll | 1
| | napi.h | io_napi (inline) | 2
| | napi.h | io_napi_busy_loop | 1
| | napi.h | io_napi_add | 1
net.c | linux/kernel.h | WARN_ON_ONCE, READ_ONCE | 5
| | linux/errno.h | EINVAL, EAGAIN, ENOTSOCK, ENOMEM | 10+
| | net/socket.c | sock_from_file | 8
| | linux/file.h | fd_install | 2
| | linux/file.h | get_unused_fd_flags | 2
| | include/linux/slab.h | kfree | 3
| | linux/net.h | sock_recvmsg | 2
| | linux/net.h | sock_sendmsg | 2
| | include/linux/socket.h | __sys_sendmsg_sock | 2
| | include/linux/socket.h | __sys_recvmsg_sock | 1
| | linux/compat.h | compat_ptr | 2
| | net/compat.h | __get_compat_msghdr | 1
| | linux/io_uring.h | io_kiocb_to_cmd, io_req_set_res | 10+
| | io_uring.h | io_put_kbuf, io_import_ubuf | 5
| | kbuf.h | io_buffer_select, io_kbuf_recycle | 3
| | alloc_cache.h | io_alloc_cache_put | 1
| | notif.h | io_notif_flush, io_alloc_notif | 3
| | filetable.h | io_fixed_fd_install | 2
| | net.c | io_net_retry | 2
| | net.c | io_netmsg_iovec_free | 2
| | net.c | io_msg_alloc_async | 3
| | net.c | io_net_import_vec | 2
| | net.c | io_msg_copy_hdr | 3
| | net.c | io_sendmsg_setup | 1
| | net.c | io_send_finish | 1
| | net.c | io_recv_finish | 1
| | net.c | io_recvmsg_multishot | 1
| | net.c | io_send_zc_cleanup | 1
net.h | linux/net.h | struct sockaddr, struct msghdr | 5
| | linux/uio.h | struct iovec | 3
| | linux/io_uring_types.h | struct io_kiocb | 18
| | net.h | io_shutdown_prep | 1 
| | net.h | io_shutdown | 1
| | net.h | io_sendmsg_prep | 1
| | net.h | io_sendmsg | 1 
| | net.h | io_recvmsg_prep | 1
| | net.h | io_recvmsg | 1
| | net.h | io_accept_prep | 1
| | net.h | io_accept | 1
| | net.h | io_connect_prep | 1
| | net.h | io_connect | 1
| | net.h | io_send_zc_prep | 1
| | net.h | io_send_zc | 1
| | net.h | io_bind_prep | 1
| | net.h | io_bind | 1
| | net.h | io_listen_prep | 1
| | net.h | io_listen | 1
| | net.h | io_netmsg_cache_free | 1
nop.c | linux/kernel.h | READ_ONCE | 2
| | linux/errno.h | EINVAL, EBADF, EFAULT | 3
| | io_uring.h | io_kiocb_to_cmd | 2
| | io_uring.h | io_req_set_res | 1
| | io_uring.h | req_set_fail | 1
| | io_uring.h | io_file_get_fixed | 1
| | io_uring.h  | io_file_get_normal | 1
| | nop.c | io_nop_prep | 1
| | nop.c | io_nop | 1
nop.h | linux/io_uring_types.h | struct io_kiocb | 2
| | linux/io_uring.h | struct io_uring_sqe | 1
| | nop.h |	io_nop_prep | 1
| | nop.h |	io_nop | 1
notif.c | linux/kernel.h | WRITE_ONCE, container_of | 3
| | linux/errno.h | EEXIST | 2
| | linux/skbuff.h | skb_zcopy | 2
| | linux/skbuff.h | skb_zcopy_init | 1
| | linux/skbuff.h | net_zcopy_get | 2
| | notif.h | io_notif_to_data | 2
| | linux/io_uring_types.h | cmd_to_io_kiocb | 4
| | io_uring.h | io_req_task_complete | 1
| | io_uring.h | __io_req_task_work_add | 1
| | io_uring.h | io_alloc_req | 1
| | io_uring.h | io_get_task_refs | 1
| | notif.c | io_notif_tw_complete | 1
| | notif.c | io_tx_ubuf_complete | 1
| | notif.c | io_link_skb | 1
| | notif.c | io_alloc_notif | 1
notif.h | include/linux/io_uring_types.h | io_kiocb_to_cmd | 1
| | rsrc.h | __io_account_mem | 1
| | notif.h	| io_notif_flush | 1
| | notif.h	| io_notif_account_mem |1
opdef.c | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/errno.h | ECANCELED | 1 
| | linux/errno.h | EOPNOTSUPP | 1 
| | io_uring.h | io_kiocb, io_uring_sqe | 2
| | io_uring.h | io_uring_sqe | 1
| | opdef.h | io_issue_def io_cold_def | 1
| | opdef.h | io_cold_def | 1
| | xattr.h | io_fsetxattr_prep, io_setxattr_prep, io_setxattr, io_fgetxattr_prep, io_fgetxattr, io_getxattr_prep, io_getxattr | 1
| | nop.h | io_nop_prep, io_nop | 1
| | statx.h | io_statx_prep, io_statx | 1
| | splice.h | io_splice_prep, io_splice, io_tee_prep, io_tee | 1
| | sync.h | io_fsync_prep, io_fsync, io_sfr_prep, io_sync_file_range | 1
| | advise.h | io_fadvise_prep, io_fadvise, io_madvise_prep, io_madvise | 1
| | openclose.h | io_openat_prep, io_openat, io_close_prep, io_close, io_openat2_prep, io_openat2 | 1
| | uring_cmd.h | io_uring_cmd_prep, io_uring_cmd | 1
| | epoll.h | io_epoll_ctl_prep, io_epoll_ctl, io_epoll_wait_prep, io_epoll_wait | 1
| | net.h | io_sendmsg_prep, io_sendmsg, io_recvmsg_prep, io_recvmsg, io_accept_prep, io_accept, io_connect_prep, io_connect, io_shutdown_prep, io_shutdown, io_socket_prep, io_socket, io_bind_prep, io_bind, io_listen_prep, io_listen | 1
| | msg_ring.h | io_msg_ring_prep, io_msg_ring | 1
| | timeout.h | io_timeout_prep, io_timeout, io_timeout_remove_prep, io_timeout_remove,io_link_timeout_prep | 1
| | poll.h | io_poll_add_prep, io_poll_add, io_poll_remove_prep, io_poll_remove | 1
| | cancel.h | io_async_cancel_prep, io_async_cancel | 1
| | rw.h | io_prep_readv, io_read, io_prep_writev, io_write, io_prep_read_fixed, io_read_fixed, io_prep_write_fixed, io_write_fixed, io_prep_read, io_prep_write, io_read_mshot_prep, io_read_mshot | 1
| | waitid.h | io_waitid_prep, io_waitid | 1
| | futex.h | io_futex_prep, io_futex_wait, io_futex_wake, io_futexv_prep, io_futexv_wait | 1
| | truncate.h | io_ftruncate_prep, io_ftruncate | 1
| | zcrx.h | io_recvzc_prep, io_recvzc | 1
| | opdef.c | io_no_issue | 1	
| | opdef.c | opdef.c	io_eopnotsupp_prep | 9	
| | opdef.c | io_uring_get_opcode | 1	
| | opdef.c | io_uring_op_supported | 1	
| | opdef.c | io_uring_optable_init | 1
opdef.h | io_uring.h | struct io_kiocb | 4		
| | opdef.h | io_issue_defs | 1	
| | opdef.h | io_cold_defs | 1	
| | opdef.h | io_uring_op_supported | 1	
| | opdef.h | io_uring_optable_init | 1	
openclose.c | linux/kernel.h | WARN_ON_ONCE | 1	
| | linux/errno.h | EINVAL, EBADF, EAGAIN, EPERM | 7	
| | linux/fs.h | filp_close, receive_fd | 1
| | linux/file.h | receive_fd | 1
| | linux/fdtable.h | files_struct, files_lookup_fd_locked, file_close_fd_locked | 1
| | fs/internal.h | build_open_flags, do_filp_open | 1
| | io_uring.h | io_kiocb_to_cmd | 10	
| | io_uring.h | io_req_set_res, req_set_fail | 6	
| | filetable.h | io_fixed_fd_install, io_fixed_fd_remove | 1
| | openclose.c	| io_openat_force_async | 3	
| | openclose.c | __io_openat_prep | 2	
| | openclose.c | io_openat_prep | 1	
| | openclose.c | io_openat2_prep | 1	
| | openclose.c | io_openat2 | 2	
| | openclose.c | io_openat | 1	
| | openclose.c | io_open_cleanup | 1	
| | openclose.c | __io_close_fixed | 2	
| | openclose.c | io_close_fixed | 1	
| | openclose.c | io_close_prep | 1	
| | openclose.c | io_close | 1	
| | openclose.c | io_install_fixed_fd_prep | 1	
| | openclose.c | io_install_fixed_fd | 1
openclose.h | io_uring.h | struct io_ring_ctx | 1
| |	openclose.h | __io_close_fixed | 1
| |	openclose.h | io_openat_prep | 1
| |	openclose.h | io_openat | 1
| |	openclose.h | io_open_cleanup | 1
| |	openclose.h | io_openat2_prep | 1
| |	openclose.h | io_openat2 | 1
| |	openclose.h | io_close_prep | 1
| |	openclose.h | io_close | 1
| |	openclose.h | io_install_fixed_fd_prep | 1
| |	openclose.h | io_install_fixed_fd | 1
poll.c | linux/kernel.h | WARN_ON_ONCE | 2	
| | linux/errno.h | EINVAL, EBADF, EAGAIN, EPERM, ENOMEM, EALREADY, ENOENT | 12	
| | linux/poll.h | vfs_poll | 3
| | linux/slab.h | kmalloc, kfree | 2
| | linux/slab.h | GFP_ATOMIC | 2	
| | linux/poll.h | poll_table_struct, EPOLL*, __poll_t | 25
| | linux/eventpoll.h | EPOLL* | 25	
| | linux/types.h | __poll_t | 4
| | linux/hash.h | hlist_node, hash_long | 3
| | trace/events/io_uring.h | trace_io_uring_* | 2	
| | uapi/linux/io_uring.h | IORING_OP_, IORING__FLAGS | 15
| | io_uring.h | io_kiocb_to_cmd, io_req_* | 32
| | alloc_cache.h | io_cache_alloc | 1
| | napi.h | io_napi_add | 2
| | opdef.h | io_issue_defs | 1
| | kbuf.h | io_kbuf_recycle | 3
| | cancel.h | io_cancel_* | 5
| | poll.c | io_poll_wake | 4
| | poll.c | io_poll_get_ownership	6
| | poll.c | __io_poll_execute	5
| | poll.c | io_poll_remove_entries | 4
| | poll.c | io_poll_cancel_req | 3
| | poll.c | io_poll_task_func | 1
| | poll.c | io_arm_poll_handler | 1
| | poll.c | io_poll_add | 1
| | poll.c | io_poll_remove | 1
poll.h | linux/io_uring_types.h | struct io_kiocb | 8
| |	linux/io_uring_types.h | struct io_uring_sqe | 2
| |	linux/io_uring_types.h | struct io_ring_ctx | 2
| |	linux/io_uring_types.h | struct io_uring_task | 1
| |	linux/io_uring_types.h | io_tw_token_t	1
| |	poll.h | struct io_poll | 3
| |	poll.h | struct async_poll | 1
| |	poll.h | io_poll_multishot_retry | 1
| |	poll.h | io_poll_add_prep | 1
| |	poll.h | io_poll_add | 1
| |	poll.h | io_poll_remove_prep | 1
| |	poll.h | io_poll_remove | 1
| |	poll.h | io_poll_cancel | 1
| |	poll.h | io_arm_poll_handler | 1
| |	poll.h | io_poll_remove_all | 1
| |	poll.h | io_poll_task_func | 1
refs.h | linux/atomic.h | atomic_*, atomic_read | 8
| | refs.h | linux/io_uring_types.h	struct io_kiocb | 9
| | refs.h | linux/io_uring_types.h	REQ_F_REFCOUNT | 6
| | refs.h | req_ref_zero_or_close_to_overflow | 5
| | refs.h | req_ref_inc_not_zero | 1
| | refs.h | req_ref_put_and_test_atomic | 1
| | refs.h | req_ref_put_and_test | 1
| | refs.h | req_ref_get | 1
| | refs.h | req_ref_put | 1
| | refs.h | __io_req_set_refcount | 1
| | refs.h | io_req_set_refcount | 1
register.c | linux/kernel.h | WARN_ON_ONCE | 2
| | linux/slab.h | kzalloc, kfree, kmalloc | 5
| | linux/uaccess.h | copy_from_user, copy_to_user	 | 2
| | linux/compat.h | compat_get_bitmap | 1
| | linux/fs.h | fget, fput, get_file | 8
| | linux/refcount.h | refcount_inc | 1
| | linux/nospec.h | array_index_nospec | 3
| | linux/io_uring.h | io_uring_fill_params | 1
| | io_uring.h | io_activate_pollwq | 1
| | rsrc.h | io_sqe_buffers_register | 3
| | sqpoll.h | io_sqpoll_wq_cpu_affinity | 1
| | eventfd.h | io_eventfd_register | 2
| | memmap.h | io_create_region_mmap_safe | 3
| | msg_ring.h | io_uring_sync_msg_ring | 1
| | opdef.h | io_uring_op_supported | 1
| | register.c | io_probe | 1
| | register.c | io_register_personality | 2
| | register.c | io_register_restrictions | 2
| | register.c | io_register_resize_rings | 1
register.h | linux/fs.h	| struct file | 1
| |	linux/io_uring_types.h	| struct io_ring_ctx | 2
| | register.h | io_eventfd_unregister | 1
| | register.h | io_unregister_personality | 1
| | register.h | io_uring_register_get_file | 1
rsrc.c | linux/kernel.h | memset | 1
| | linux/fs.h | fget, fput | 4
| | linux/slab.h | kvmalloc, kvfree, kvmalloc_array | 5
| | linux/mm.h | unpin_user_page, unpin_user_pages, PageCompound, compound_head, page_size, folio_nr_pages, folio_shift, folio_size, folio_page_idx | 9
| | linux/io_uring.h | io_is_uring_fops | 1
| | linux/uio.h | iovec_from_user | 2
| | linux/bio.h | bvec_set_page, bio_vec, blk_rq_nr_phys_segments, blk_rq_bytes, rq_data_dir, rq_for_each_bvec | 6
| | linux/overflow.h | check_add_overflow |3
| | linux/errno.h | ENOMEM, EFAULT, EINVAL, EBADF, ENXIO, EOVERFLOW, EMFILE | 7
| | linux/compat.h | compat_iovec | 1
| | linux/limits.h | rlimit | 1
| | uapi/linux/io_uring.h | IORING_REGISTER_FILES_SKIP, IORING_RSRC_FILE, IORING_RSRC_BUFFER | 3
| | io_uring.h | io_alloc_cache_init, io_alloc_cache_free, io_cache_alloc, io_cache_free | 4
| | openclose.h | io_close_fixed | 1
| | memmap.h | io_post_aux_cqe | 1
| | register.h | io_uring_register_get_file | | 1
| | rsrc.h | io_account_mem | 2
| | rsrc.h | io_buffer_validate	| 3
| | rsrc.h | io_release_ubuf | 1
| | rsrc.h | io_alloc_imu	| 3
| | rsrc.h | io_free_imu | 2
| | rsrc.h | io_buffer_unmap | 2
| | rsrc.h | io_rsrc_node_alloc | 5
| | rsrc.h | io_rsrc_cache_init | 1
| | rsrc.h | io_rsrc_cache_free | 1
| | rsrc.h | io_rsrc_data_free | 2
| | rsrc.h | io_rsrc_data_alloc | 2
| | rsrc.h | __io_sqe_files_update | 2
| | rsrc.h | __io_sqe_buffers_update | 2
| | rsrc.h | __io_register_rsrc_update | 2
| | rsrc.h | io_sqe_buffer_register | 2
| | rsrc.h | io_free_rsrc_node | 1
| | rsrc.h | io_sqe_files_unregister | 1
| | rsrc.h | io_sqe_files_register | 1
| | rsrc.h | io_sqe_buffers_unregister | 1
| | rsrc.h | io_sqe_buffers_register | 1
| | rsrc.h | headpage_already_acct | 1
| | rsrc.h | io_buffer_account_pin | 1
| | rsrc.h | io_coalesce_buffer | 1
| | rsrc.h | io_check_coalesce_buffer | 1
| | rsrc.h | io_import_fixed | 2
| | rsrc.h | io_find_buf_node | 2
| | rsrc.h | io_import_reg_buf | 1
| | rsrc.h | lock_two_rings | 1
| | rsrc.h | io_clone_buffers | 1
| | rsrc.h | io_register_clone_buffers | 1
| | rsrc.h | io_vec_free | 1
| | rsrc.h | io_vec_realloc | 2
| | rsrc.h | io_vec_fill_bvec | 1
| | rsrc.h | io_estimate_bvec_size | 1
| | rsrc.h | io_vec_fill_kern_bvec | 1
| | rsrc.h | iov_kern_bvec_size | 1
| | rsrc.h | io_kern_bvec_size | 1
| | rsrc.h | io_import_reg_vec | 1
| | rsrc.h | io_prep_reg_iovec | 1
rsrc.h | linux/io_uring_types.h | struct io_ring_ctx | 12
| | linux/io_uring_types.h | struct io_kiocb | 6
| | linux/lockdep.h | lockdep_assert_held | 1
| | linux/uaccess.h | array_index_nospec | 1
| | linux/refcount.h | refcount_t (via struct io_mapped_ubuf) | 1	
| | rsrc.h | io_rsrc_cache_init | 1	
| | rsrc.h | io_rsrc_cache_free | 1	
| | rsrc.h | io_rsrc_node_alloc | 1	
| | rsrc.h | io_free_rsrc_node | 4	
| | rsrc.h | io_sqe_buffers_register | 1	
| | rsrc.h | io_sqe_buffers_unregister | 1
| | rsrc.h | io_sqe_files_register | 1
| | rsrc.h | io_sqe_files_unregister | 1
| | rsrc.h | io_import_reg_buf | 1
| | rsrc.h | io_import_reg_vec | 1
| | rsrc.h | io_files_update | 1
| | rsrc.h | io_put_rsrc_node | 3
| | rsrc.h | io_req_put_rsrc_nodes | 1
| | rsrc.h | io_req_assign_buf_node | 1
| | rsrc.c | io_unaccount_mem	2


Continue with the list untill all functions used in each source are listed.