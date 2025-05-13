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
advise.c | mm/madvise.c | do_madvise | 1 |
| | io_uring/advise.c | io_fadvise_force_async | 2 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 4 |
| | io_uring/io_uring.h | io_req_set_res | 2 |
| | include/asm-generic/rwonce.h | READ_ONCE | 8 |
| | io_uring/io_uring.h | req_set_fail | 1 |
| | mm/fadvise.c | vfs_fadvise | 1 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 2 |
alloc_cache.c | arch/alpha/kernel/pci_iommu.c | free | 1 |
| | io_uring/alloc_cache.h | io_alloc_cache_get | 1 |
| | include/linux/slab.h | kmalloc | 1 |
| | drivers/vdpa/mlx5/core/mr.c | kvfree | 1 |
| | include/linux/slab.h | kvmalloc_array | 1 |
| | arch/alpha/include/asm/string.h | memset | 1 |
alloc_cache.h | io_uring/alloc_cache.h | io_alloc_cache_get | 1 |
| | io_uring/alloc_cache.c | io_alloc_cache_init | 1 |
| | io_uring/alloc_cache.h | io_alloc_cache_put | 1 |
| | io_uring/alloc_cache.c | io_cache_alloc_new | 2 |
| | include/linux/kasan.h | kasan_mempool_poison_object | 1 |
| | include/linux/kasan.h | kasan_mempool_unpoison_object | 1 |
| | include/linux/slab.h | kfree | 1 |
| | arch/alpha/include/asm/string.h | memset | 1 |
cancel.c | arch/mips/boot/tools/relocs.h | ARRAY_SIZE | 2 |
| | include/linux/atomic/atomic-instrumented.h | atomic_inc_return | 3 |
| | drivers/block/drbd/drbd_int.h | cancel | 2 |
| | drivers/gpu/drm/radeon/mkregtable.c | container_of | 1 |
| | include/linux/uaccess.h | copy_from_user | 1 |
| | include/linux/wait.h | DEFINE_WAIT | 1 |
| | arch/alpha/kernel/osf_sys.c | fget | 1 |
| | kernel/sched/wait.c | finish_wait | 1 |
| | fs/file_table.c | fput | 1 |
| | include/linux/list.h | hlist_del_init | 1 |
| | include/linux/list.h | hlist_for_each_entry_safe | 2 |
| | io_uring/cancel.c | __io_async_cancel | 2 |
| | io_uring/cancel.c | io_async_cancel_one | 2 |
| | io_uring/cancel.h | io_cancel_match_sequence | 1 |
| | io_uring/cancel.c | io_cancel_req_match | 2 |
| | io_uring/io_uring.c | io_file_get_fixed | 1 |
| | io_uring/io_uring.c | io_file_get_normal | 1 |
| | io_uring/futex.c | io_futex_cancel | 1 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 2 |
| | io_uring/io_uring.c | io_match_task_safe | 1 |
| | io_uring/poll.c | io_poll_cancel | 1 |
| | io_uring/io_uring.h | io_req_set_res | 1 |
| | io_uring/io_uring.h | io_ring_submit_lock | 2 |
| | io_uring/io_uring.h | io_ring_submit_unlock | 2 |
| | io_uring/rsrc.h | io_rsrc_node_lookup | 1 |
| | io_uring/io_uring.c | io_run_task_work_sig | 1 |
| | io_uring/filetable.h | io_slot_file | 1 |
| | io_uring/cancel.c | __io_sync_cancel | 2 |
| | io_uring/timeout.c | io_timeout_cancel | 1 |
| | io_uring/cancel.c | io_try_cancel | 1 |
| | io_uring/waitid.c | io_waitid_cancel | 1 |
| | io_uring/io-wq.c | io_wq_cancel_cb | 1 |
| | io_uring/io-wq.h | io_wq_current_is_worker | 1 |
| | include/linux/ktime.h | ktime_add_ns | 1 |
| | include/linux/timekeeping.h | ktime_get_ns | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | list_for_each_entry | 1 |
| | include/linux/lockdep.h | lockdep_assert_held | 1 |
| | drivers/block/aoe/aoenet.c | __must_hold | 1 |
| | include/linux/mutex.h | mutex_lock | 2 |
| | include/linux/mutex.h | mutex_unlock | 1 |
| | kernel/sched/wait.c | prepare_to_wait | 1 |
| | include/asm-generic/rwonce.h | READ_ONCE | 4 |
| | io_uring/io_uring.h | req_set_fail | 1 |
| | kernel/time/sleep_timeout.c | schedule_hrtimeout | 1 |
| | drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.h | spin_lock | 1 |
| | include/linux/spinlock.h | spin_unlock | 1 |
| | include/linux/ktime.h | timespec64_to_ktime | 1 |
| | include/linux/compiler.h | unlikely | 2 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 1 |
cancel.h | io_uring/cancel.c | io_cancel_remove | 1 |
epoll.c | include/linux/uaccess.h | copy_from_user | 1 |
| | fs/eventpoll.c | do_epoll_ctl | 1 |
| | fs/eventpoll.c | epoll_sendevents | 1 |
| | include/linux/eventpoll.h | ep_op_has_event | 1 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 4 |
| | io_uring/io_uring.h | io_req_set_res | 2 |
| | include/asm-generic/rwonce.h | READ_ONCE | 6 |
| | io_uring/io_uring.h | req_set_fail | 2 |
| | include/linux/kernel.h | u64_to_user_ptr | 2 |
eventfd.c | include/linux/atomic/atomic-instrumented.h | atomic_fetch_or | 1 |
| | include/linux/atomic/atomic-instrumented.h | atomic_set | 1 |
| | drivers/comedi/drivers/ni_routing/tools/convert_c_to_py.c | BIT | 1 |
| | kernel/rcu/tiny.c | call_rcu | 1 |
| | include/linux/rcupdate.h | call_rcu_hurry | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | container_of | 2 |
| | include/linux/uaccess.h | copy_from_user | 1 |
| | fs/eventfd.c | eventfd_ctx_fdget | 1 |
| | fs/eventfd.c | eventfd_ctx_put | 1 |
| | include/linux/eventfd.h | eventfd_signal_allowed | 1 |
| | fs/eventfd.c | eventfd_signal_mask | 2 |
| | io_uring/eventfd.c | io_eventfd_grab | 2 |
| | io_uring/eventfd.c | io_eventfd_put | 3 |
| | io_uring/eventfd.c | io_eventfd_release | 2 |
| | io_uring/eventfd.c | __io_eventfd_signal | 2 |
| | io_uring/eventfd.c | io_eventfd_trigger | 1 |
| | io_uring/io-wq.h | io_wq_current_is_worker | 1 |
| | crypto/asymmetric_keys/x509_parser.h | IS_ERR | 1 |
| | include/linux/slab.h | kfree | 2 |
| | include/linux/slab.h | kmalloc | 1 |
| | include/linux/lockdep.h | lockdep_is_held | 2 |
| | include/linux/err.h | PTR_ERR | 1 |
| | include/linux/rcupdate.h | rcu_assign_pointer | 2 |
| | include/linux/rcupdate.h | rcu_dereference | 1 |
| | include/linux/rcupdate.h | rcu_dereference_protected | 2 |
| | include/linux/rcupdate.h | rcu_read_lock | 1 |
| | include/linux/rcupdate.h | rcu_read_unlock | 2 |
| | include/asm-generic/rwonce.h | READ_ONCE | 1 |
| | include/linux/refcount.h | refcount_dec_and_test | 1 |
| | include/linux/refcount.h | refcount_inc_not_zero | 1 |
| | include/linux/refcount.h | refcount_set | 1 |
| | drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.h | spin_lock | 2 |
| | include/linux/spinlock.h | spin_unlock | 2 |
fdinfo.c | io_uring/fdinfo.c | common_tracking_show_fdinfo | 2 |
| | include/linux/uidgid.h | from_kgid_munged | 5 |
| | include/linux/uidgid.h | from_kuid_munged | 4 |
| | kernel/sys.c | getrusage | 1 |
| | include/linux/list.h | hlist_for_each_entry | 1 |
| | io_uring/filetable.h | io_slot_file | 1 |
| | include/linux/io_uring.h | io_uring_get_opcode | 1 |
| | io_uring/fdinfo.c | io_uring_show_cred | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | list_for_each_entry | 1 |
| | arch/arc/include/asm/arcregs.h | min | 2 |
| | include/linux/mutex.h | mutex_trylock | 1 |
| | include/linux/mutex.h | mutex_unlock | 1 |
| | io_uring/fdinfo.c | napi_show_fdinfo | 1 |
| | include/asm-generic/rwonce.h | READ_ONCE | 6 |
| | fs/seq_file.c | seq_file_path | 1 |
| | fs/seq_file.c | seq_printf | 32 |
| | fs/seq_file.c | seq_putc | 1 |
| | fs/seq_file.c | seq_put_decimal_ull | 9 |
| | fs/seq_file.c | seq_put_hex_ll | 1 |
| | include/linux/seq_file.h | seq_puts | 9 |
| | include/linux/seq_file.h | seq_user_ns | 1 |
| | drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.h | spin_lock | 1 |
| | include/linux/spinlock.h | spin_unlock | 1 |
| | include/linux/task_work.h | task_work_pending | 1 |
| | include/linux/xarray.h | xa_empty | 1 |
| | include/linux/xarray.h | xa_for_each | 1 |
filetable.c | include/linux/bitmap.h | bitmap_free | 1 |
| | lib/bitmap.c | bitmap_zalloc | 1 |
| | include/linux/overflow.h | check_add_overflow | 1 |
| | include/linux/uaccess.h | copy_from_user | 1 |
| | arch/arm/include/asm/bitops.h | find_next_zero_bit | 1 |
| | fs/file_table.c | fput | 1 |
| | io_uring/filetable.h | io_file_bitmap_clear | 1 |
| | io_uring/filetable.c | io_file_bitmap_get | 1 |
| | io_uring/filetable.h | io_file_bitmap_set | 1 |
| | io_uring/filetable.h | io_file_table_set_alloc_range | 1 |
| | io_uring/filetable.c | __io_fixed_fd_install | 1 |
| | io_uring/filetable.h | io_fixed_file_set | 1 |
| | io_uring/filetable.c | io_install_fixed_file | 1 |
| | include/linux/io_uring.h | io_is_uring_fops | 1 |
| | io_uring/rsrc.h | io_reset_rsrc_node | 2 |
| | io_uring/io_uring.h | io_ring_submit_lock | 1 |
| | io_uring/io_uring.h | io_ring_submit_unlock | 1 |
| | io_uring/rsrc.c | io_rsrc_data_alloc | 1 |
| | io_uring/rsrc.c | io_rsrc_data_free | 2 |
| | io_uring/rsrc.c | io_rsrc_node_alloc | 1 |
| | io_uring/rsrc.h | io_rsrc_node_lookup | 1 |
| | drivers/block/aoe/aoenet.c | __must_hold | 1 |
| | include/linux/compiler.h | unlikely | 3 |
filetable.h | include/linux/bitops.h | __clear_bit | 1 |
| | io_uring/io_uring.c | io_file_get_flags | 1 |
| | include/linux/bitops.h | __set_bit | 1 |
| | arch/x86/boot/bitops.h | test_bit | 2 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 2 |
fs.c | fs/namei.c | do_linkat | 1 |
| | fs/namei.c | do_mkdirat | 1 |
| | fs/namei.c | do_renameat2 | 1 |
| | fs/namei.c | do_rmdir | 1 |
| | fs/namei.c | do_symlinkat | 1 |
| | fs/namei.c | do_unlinkat | 1 |
| | crypto/af_alg.c | getname | 7 |
| | fs/namei.c | getname_uflags | 1 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 14 |
| | io_uring/io_uring.h | io_req_set_res | 5 |
| | crypto/asymmetric_keys/x509_parser.h | IS_ERR | 8 |
| | include/linux/err.h | PTR_ERR | 8 |
| | fs/namei.c | putname | 9 |
| | include/asm-generic/rwonce.h | READ_ONCE | 19 |
| | include/linux/kernel.h | u64_to_user_ptr | 8 |
| | include/linux/compiler.h | unlikely | 5 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 5 |
futex.c | drivers/gpu/drm/radeon/mkregtable.c | container_of | 1 |
| | kernel/futex/futex.h | futex2_to_flags | 1 |
| | kernel/futex/futex.h | futex_flags_valid | 1 |
| | kernel/futex/syscalls.c | futex_parse_waitv | 1 |
| | kernel/futex/futex.h | futex_queue | 1 |
| | kernel/futex/core.c | futex_unqueue | 1 |
| | kernel/futex/waitwake.c | futex_unqueue_multiple | 1 |
| | kernel/futex/futex.h | futex_validate_input | 2 |
| | kernel/futex/waitwake.c | futex_wait_multiple_setup | 1 |
| | kernel/futex/waitwake.c | futex_wait_setup | 1 |
| | kernel/futex/waitwake.c | futex_wake | 1 |
| | kernel/futex/waitwake.c | __futex_wake_mark | 2 |
| | include/linux/list.h | hlist_add_head | 2 |
| | include/linux/list.h | hlist_del_init | 2 |
| | io_uring/alloc_cache.c | io_alloc_cache_free | 1 |
| | io_uring/alloc_cache.c | io_alloc_cache_init | 1 |
| | io_uring/alloc_cache.h | io_cache_alloc | 1 |
| | io_uring/alloc_cache.h | io_cache_free | 1 |
| | io_uring/cancel.c | io_cancel_remove | 1 |
| | io_uring/cancel.c | io_cancel_remove_all | 1 |
| | io_uring/futex.c | __io_futex_complete | 2 |
| | io_uring/futex.c | io_futexv_claim | 2 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 8 |
| | io_uring/io_uring.h | io_req_set_res | 8 |
| | io_uring/io_uring.c | io_req_task_complete | 1 |
| | io_uring/io_uring.h | io_req_task_work_add | 3 |
| | io_uring/io_uring.h | io_ring_submit_lock | 2 |
| | io_uring/io_uring.h | io_ring_submit_unlock | 4 |
| | io_uring/io_uring.h | io_tw_lock | 2 |
| | include/linux/slab.h | kcalloc | 1 |
| | include/linux/slab.h | kfree | 4 |
| | include/asm-generic/rwonce.h | READ_ONCE | 6 |
| | io_uring/io_uring.h | req_set_fail | 3 |
| | include/linux/sched.h | __set_current_state | 1 |
| | arch/alpha/include/asm/bitops.h | test_and_set_bit_lock | 1 |
| | arch/x86/boot/bitops.h | test_bit | 1 |
| | include/linux/kernel.h | u64_to_user_ptr | 2 |
| | include/linux/compiler.h | unlikely | 5 |
io_uring.c | arch/parisc/kernel/firmware.c | __acquires | 1 |
| | include/linux/linkage.h | ALIGN | 1 |
| | kernel/workqueue.c | alloc_workqueue | 1 |
| | fs/anon_inodes.c | anon_inode_create_getfile | 1 |
| | include/linux/nospec.h | array_index_nospec | 4 |
| | drivers/gpu/drm/imagination/pvr_stream.h | array_size | 3 |
| | arch/mips/boot/tools/relocs.h | ARRAY_SIZE | 2 |
| | include/linux/atomic/atomic-instrumented.h | atomic_andnot | 3 |
| | include/linux/atomic/atomic-instrumented.h | atomic_dec | 2 |
| | include/linux/atomic/atomic-instrumented.h | atomic_inc | 2 |
| | include/linux/atomic/atomic-instrumented.h | atomic_or | 8 |
| | include/linux/atomic/atomic-instrumented.h | atomic_read | 7 |
| | include/linux/atomic/atomic-instrumented.h | atomic_set | 6 |
| | include/linux/audit.h | audit_uring_entry | 1 |
| | include/linux/audit.h | audit_uring_exit | 1 |
| | kernel/sched/wait.c | autoremove_wake_function | 1 |
| | drivers/comedi/drivers/ni_routing/tools/convert_c_to_py.c | BIT | 5 |
| | block/blk-core.c | blk_finish_plug | 1 |
| | block/blk-core.c | blk_start_plug_nr_ios | 1 |
| | arch/mips/include/asm/bug.h | BUG_ON | 2 |
| | arch/x86/include/asm/kvm-x86-ops.h | BUILD_BUG_ON | 16 |
| | io_uring/io_uring.c | BUILD_BUG_SQE_ELEM | 43 |
| | io_uring/io_uring.c | BUILD_BUG_SQE_ELEM_SIZE | 1 |
| | io_uring/io_uring.c | __BUILD_BUG_VERIFY_OFFSET_SIZE | 2 |
| | arch/powerpc/kernel/iommu.c | capable | 1 |
| | include/linux/overflow.h | check_add_overflow | 2 |
| | include/linux/overflow.h | check_shl_overflow | 1 |
| | drivers/media/platform/ti/omap3isp/ispccdc.h | clamp | 1 |
| | arch/alpha/include/asm/agp_backend.h | cleanup | 1 |
| | arch/alpha/include/asm/bitops.h | clear_bit | 2 |
| | arch/arm/mach-rpc/ecard.c | complete | 2 |
| | include/linux/sched.h | cond_resched | 8 |
| | drivers/gpu/drm/radeon/mkregtable.c | container_of | 20 |
| | include/linux/uaccess.h | copy_from_user | 3 |
| | include/linux/uaccess.h | copy_to_user | 1 |
| | io_uring/io_uring.c | ctx_flush_and_put | 3 |
| | include/linux/cred.h | current_cred | 1 |
| | io_uring/io_uring.c | current_pending_io | 1 |
| | include/linux/cred.h | current_user | 1 |
| | include/linux/wait.h | DEFINE_WAIT | 1 |
| | include/linux/hrtimer.h | destroy_hrtimer_on_stack | 1 |
| | include/linux/err.h | ERR_PTR | 2 |
| | arch/arm/vdso/vdsomunge.c | fail | 1 |
| | fs/file.c | fd_install | 1 |
| | arch/alpha/kernel/osf_sys.c | fget | 2 |
| | include/linux/fs.h | file_inode | 3 |
| | kernel/sched/wait.c | finish_wait | 2 |
| | kernel/workqueue.c | flush_delayed_work | 4 |
| | fs/file_table.c | fput | 2 |
| | kernel/user.c | free_uid | 1 |
| | arch/mips/include/asm/mips-r2-to-r6-emul.h | func | 1 |
| | include/linux/cred.h | get_cred | 1 |
| | include/linux/cred.h | get_current_cred | 1 |
| | include/linux/sched/task.h | get_task_struct | 1 |
| | kernel/time/time.c | get_timespec64 | 1 |
| | drivers/s390/block/dasd_eckd.c | get_uid | 1 |
| | fs/file.c | get_unused_fd_flags | 1 |
| | include/linux/uidgid.h | gid_valid | 1 |
| | drivers/gpu/drm/i915/i915_vma_resource.h | guard | 1 |
| | kernel/time/hrtimer.c | hrtimer_cancel | 1 |
| | include/linux/hrtimer.h | hrtimer_set_expires | 1 |
| | include/linux/hrtimer.h | hrtimer_set_expires_range_ns | 1 |
| | kernel/time/hrtimer.c | hrtimer_setup_on_stack | 2 |
| | include/linux/hrtimer.h | hrtimer_start_expires | 1 |
| | include/linux/hrtimer.h | hrtimer_update_function | 1 |
| | include/linux/log2.h | ilog2 | 1 |
| | arch/sparc/include/asm/compat.h | in_compat_syscall | 2 |
| | include/linux/indirect_call_wrapper.h | INDIRECT_CALL_2 | 2 |
| | include/linux/cred.h | in_group_p | 1 |
| | drivers/bluetooth/hci_nokia.c | init_completion | 2 |
| | include/linux/workqueue.h | INIT_DELAYED_WORK | 1 |
| | include/linux/list.h | INIT_HLIST_HEAD | 4 |
| | drivers/gpu/drm/radeon/mkregtable.c | INIT_LIST_HEAD | 7 |
| | include/linux/llist.h | init_llist_head | 1 |
| | include/linux/task_work.h | init_task_work | 2 |
| | include/linux/wait.h | init_waitqueue_func_entry | 1 |
| | include/linux/wait.h | init_waitqueue_head | 3 |
| | include/linux/workqueue.h | INIT_WORK | 1 |
| | io_uring/slist.h | INIT_WQ_LIST | 3 |
| | io_uring/io_uring.c | io_account_cq_overflow | 1 |
| | io_uring/io_uring.c | io_activate_pollwq | 1 |
| | io_uring/io_uring.c | io_allocate_scq_urings | 1 |
| | io_uring/alloc_cache.c | io_alloc_cache_free | 5 |
| | io_uring/alloc_cache.c | io_alloc_cache_init | 5 |
| | io_uring/io_uring.c | io_alloc_hash_table | 1 |
| | io_uring/io_uring.h | io_alloc_req | 1 |
| | io_uring/io_uring.h | io_allowed_defer_tw_run | 1 |
| | io_uring/io_uring.h | io_allowed_run_tw | 2 |
| | io_uring/io_uring.c | __io_arm_ltimeout | 1 |
| | io_uring/io_uring.c | io_arm_ltimeout | 2 |
| | io_uring/poll.c | io_arm_poll_handler | 3 |
| | io_uring/io_uring.c | io_assign_file | 2 |
| | io_uring/alloc_cache.h | io_cache_free | 1 |
| | io_uring/io_uring.c | io_cancel_defer_files | 1 |
| | io_uring/io_uring.c | io_check_restriction | 1 |
| | io_uring/io_uring.c | io_clean_op | 1 |
| | io_uring/io_uring.h | io_commit_cqring | 2 |
| | io_uring/io_uring.h | io_commit_cqring_flush | 2 |
| | io_uring/io_uring.c | io_commit_sqring | 1 |
| | io_uring/io_uring.c | __io_cq_lock | 2 |
| | io_uring/io_uring.c | io_cq_lock | 4 |
| | io_uring/io_uring.c | io_cqring_do_overflow_flush | 2 |
| | io_uring/io_uring.c | io_cqring_event_overflow | 3 |
| | io_uring/io_uring.c | __io_cqring_events | 3 |
| | io_uring/io_uring.c | io_cqring_events | 2 |
| | io_uring/io_uring.c | __io_cqring_events_user | 2 |
| | io_uring/io_uring.c | __io_cqring_overflow_flush | 3 |
| | io_uring/io_uring.c | io_cqring_overflow_kill | 2 |
| | io_uring/io_uring.c | io_cqring_schedule_timeout | 1 |
| | io_uring/io_uring.c | io_cqring_timer_wakeup | 1 |
| | io_uring/io_uring.c | io_cqring_wait | 1 |
| | io_uring/io_uring.c | __io_cqring_wait_schedule | 1 |
| | io_uring/io_uring.c | io_cqring_wait_schedule | 1 |
| | io_uring/io_uring.h | io_cqring_wake | 2 |
| | io_uring/io_uring.c | __io_cq_unlock_post | 2 |
| | io_uring/io_uring.c | io_cq_unlock_post | 4 |
| | io_uring/memmap.c | io_create_region | 2 |
| | io_uring/kbuf.c | io_destroy_buffers | 1 |
| | io_uring/timeout.c | io_disarm_next | 1 |
| | io_uring/rw.c | io_do_iopoll | 2 |
| | io_uring/io_uring.c | io_drain_req | 1 |
| | io_uring/eventfd.c | io_eventfd_flush_signal | 1 |
| | io_uring/eventfd.c | io_eventfd_signal | 1 |
| | io_uring/eventfd.c | io_eventfd_unregister | 1 |
| | io_uring/io_uring.h | io_extract_req | 1 |
| | io_uring/io_uring.c | __io_fallback_tw | 3 |
| | io_uring/io_uring.c | io_fallback_tw | 2 |
| | io_uring/io_uring.h | io_file_can_poll | 2 |
| | io_uring/io_uring.c | io_file_get_fixed | 1 |
| | io_uring/io_uring.c | io_file_get_flags | 1 |
| | io_uring/io_uring.c | io_file_get_normal | 1 |
| | io_uring/io_uring.c | io_fill_cqe_aux | 3 |
| | io_uring/io_uring.h | io_fill_cqe_req | 2 |
| | io_uring/timeout.c | io_flush_timeouts | 1 |
| | io_uring/io_uring.h | io_for_each_link | 4 |
| | io_uring/io_uring.c | io_free_alloc_caches | 2 |
| | io_uring/io_uring.c | io_free_batch_list | 1 |
| | io_uring/memmap.c | io_free_region | 3 |
| | io_uring/io_uring.c | io_free_req | 1 |
| | io_uring/futex.c | io_futex_cache_free | 1 |
| | io_uring/futex.c | io_futex_cache_init | 1 |
| | io_uring/futex.c | io_futex_remove_all | 1 |
| | io_uring/io_uring.h | io_get_cqe | 1 |
| | io_uring/io_uring.h | io_get_cqe_overflow | 1 |
| | io_uring/io_uring.c | io_get_ext_arg | 1 |
| | io_uring/io_uring.c | io_get_ext_arg_reg | 1 |
| | io_uring/io_uring.c | io_get_sequence | 1 |
| | io_uring/io_uring.c | io_get_sqe | 1 |
| | io_uring/io_uring.h | io_get_task_refs | 1 |
| | io_uring/io_uring.h | io_get_time | 1 |
| | io_uring/io_uring.c | io_handle_tw_list | 1 |
| | io_uring/io_uring.h | io_has_work | 3 |
| | io_uring/io_uring.c | io_init_drain | 1 |
| | io_uring/io_uring.c | io_init_fail_req | 9 |
| | io_uring/io_uring.c | io_init_req | 1 |
| | io_uring/io_uring.c | io_iopoll_check | 1 |
| | io_uring/io_uring.c | io_iopoll_req_issued | 1 |
| | io_uring/io_uring.c | io_iopoll_try_reap_events | 1 |
| | io_uring/io_uring.c | __io_issue_sqe | 2 |
| | io_uring/io_uring.c | io_issue_sqe | 2 |
| | include/linux/io_uring.h | io_is_uring_fops | 2 |
| | io_uring/kbuf.c | io_kbuf_drop_legacy | 1 |
| | io_uring/kbuf.h | io_kbuf_recycle | 2 |
| | io_uring/timeout.c | io_kill_timeouts | 1 |
| | io_uring/io_uring.h | io_local_work_pending | 7 |
| | io_uring/io_uring.c | io_match_linked | 2 |
| | io_uring/io_uring.c | io_match_task_safe | 2 |
| | io_uring/io_uring.c | io_move_task_work_from_local | 1 |
| | io_uring/napi.h | io_napi_busy_loop | 1 |
| | io_uring/napi.c | io_napi_free | 1 |
| | io_uring/napi.c | io_napi_init | 1 |
| | io_uring/poll.c | io_poll_remove_all | 1 |
| | io_uring/io_uring.h | io_poll_wq_wake | 1 |
| | io_uring/io_uring.c | io_preinit_req | 1 |
| | io_uring/io_uring.c | io_prep_async_link | 2 |
| | io_uring/io_uring.c | io_prep_async_work | 2 |
| | io_uring/io_uring.c | __io_prep_linked_timeout | 2 |
| | io_uring/io_uring.c | io_prep_linked_timeout | 2 |
| | io_uring/io_uring.h | io_put_file | 1 |
| | io_uring/kbuf.h | io_put_kbuf | 1 |
| | io_uring/io_uring.c | io_put_task | 1 |
| | io_uring/io_uring.c | io_queue_async | 1 |
| | io_uring/io_uring.c | io_queue_deferred | 1 |
| | io_uring/io_uring.c | io_queue_iowq | 5 |
| | io_uring/timeout.c | io_queue_linked_timeout | 3 |
| | io_uring/io_uring.c | io_queue_next | 1 |
| | io_uring/io_uring.c | io_queue_sqe | 2 |
| | io_uring/io_uring.c | io_queue_sqe_fallback | 3 |
| | io_uring/memmap.h | io_region_get_ptr | 2 |
| | io_uring/io_uring.c | io_req_add_to_cache | 3 |
| | io_uring/rsrc.h | io_req_assign_rsrc_node | 1 |
| | io_uring/io_uring.h | io_req_cache_empty | 2 |
| | io_uring/io_uring.c | io_req_caches_free | 2 |
| | io_uring/io_uring.h | io_req_complete_defer | 3 |
| | io_uring/io_uring.c | io_req_complete_post | 1 |
| | io_uring/io_uring.c | io_req_cqe_overflow | 2 |
| | io_uring/io_uring.c | io_req_defer_failed | 5 |
| | io_uring/io_uring.c | io_req_find_next | 2 |
| | io_uring/io_uring.c | __io_req_find_next_prep | 1 |
| | io_uring/io_uring.c | io_req_local_work_add | 1 |
| | io_uring/io_uring.c | io_req_normal_work_add | 1 |
| | io_uring/rsrc.h | io_req_put_rsrc_nodes | 1 |
| | io_uring/refs.h | __io_req_set_refcount | 2 |
| | io_uring/refs.h | io_req_set_refcount | 1 |
| | io_uring/io_uring.h | io_req_set_res | 3 |
| | io_uring/io_uring.c | io_req_task_queue | 4 |
| | io_uring/io_uring.c | io_req_task_queue_fail | 4 |
| | io_uring/io_uring.c | __io_req_task_work_add | 1 |
| | io_uring/io_uring.h | io_req_task_work_add | 5 |
| | io_uring/io_uring.c | io_req_track_inflight | 1 |
| | io_uring/tctx.c | io_ring_add_registered_file | 1 |
| | io_uring/io_uring.c | io_ring_ctx_alloc | 1 |
| | io_uring/io_uring.c | io_ring_ctx_free | 1 |
| | io_uring/io_uring.c | io_ring_ctx_wait_and_kill | 2 |
| | io_uring/io_uring.c | io_rings_free | 3 |
| | io_uring/io_uring.h | io_ring_submit_lock | 1 |
| | io_uring/io_uring.h | io_ring_submit_unlock | 1 |
| | io_uring/rsrc.c | io_rsrc_cache_free | 1 |
| | io_uring/rsrc.c | io_rsrc_cache_init | 1 |
| | io_uring/rsrc.h | io_rsrc_node_lookup | 1 |
| | io_uring/io_uring.c | __io_run_local_work | 2 |
| | io_uring/io_uring.c | io_run_local_work | 4 |
| | io_uring/io_uring.c | io_run_local_work_continue | 2 |
| | io_uring/io_uring.c | io_run_local_work_locked | 2 |
| | io_uring/io_uring.c | __io_run_local_work_loop | 2 |
| | io_uring/io_uring.h | io_run_task_work | 6 |
| | io_uring/io_uring.h | io_should_terminate_tw | 1 |
| | io_uring/io_uring.h | io_should_wake | 3 |
| | io_uring/zcrx.c | io_shutdown_zcrx_ifqs | 1 |
| | io_uring/filetable.h | io_slot_file | 1 |
| | io_uring/filetable.h | io_slot_flags | 1 |
| | io_uring/rsrc.c | io_sqe_buffers_unregister | 1 |
| | io_uring/rsrc.c | io_sqe_files_unregister | 1 |
| | io_uring/sqpoll.c | io_sq_offload_create | 1 |
| | io_uring/sqpoll.c | io_sqpoll_wait_sq | 1 |
| | io_uring/io_uring.h | io_sqring_entries | 1 |
| | io_uring/io_uring.h | io_sqring_full | 1 |
| | io_uring/sqpoll.c | io_sq_thread_finish | 1 |
| | io_uring/sqpoll.c | io_sq_thread_park | 1 |
| | io_uring/sqpoll.c | io_sq_thread_unpark | 1 |
| | io_uring/io_uring.c | io_submit_fail_init | 1 |
| | io_uring/io_uring.h | io_submit_flush_completions | 4 |
| | io_uring/io_uring.c | io_submit_sqe | 1 |
| | io_uring/io_uring.c | io_submit_sqes | 1 |
| | io_uring/io_uring.c | io_submit_state_end | 1 |
| | io_uring/io_uring.c | io_submit_state_start | 1 |
| | io_uring/io_uring.h | io_task_work_pending | 1 |
| | io_uring/io_uring.h | io_tw_lock | 3 |
| | io_uring/register.c | io_unregister_personality | 1 |
| | io_uring/zcrx.c | io_unregister_zcrx_ifqs | 1 |
| | io_uring/tctx.c | __io_uring_add_tctx_node | 1 |
| | io_uring/tctx.h | io_uring_add_tctx_node | 1 |
| | io_uring/io_uring.c | io_uring_allowed | 1 |
| | io_uring/io_uring.c | io_uring_cancel_generic | 1 |
| | io_uring/tctx.c | io_uring_clean_tctx | 1 |
| | io_uring/io_uring.c | io_uring_create | 1 |
| | io_uring/tctx.c | io_uring_del_tctx_node | 1 |
| | io_uring/io_uring.c | io_uring_drop_tctx_refs | 3 |
| | io_uring/io_uring.c | io_uring_fill_params | 1 |
| | io_uring/tctx.c | __io_uring_free | 1 |
| | io_uring/io_uring.c | io_uring_get_file | 1 |
| | io_uring/io_uring.c | io_uring_install_fd | 1 |
| | io_uring/opdef.c | io_uring_optable_init | 1 |
| | io_uring/io_uring.c | io_uring_sanitise_params | 1 |
| | io_uring/io_uring.c | io_uring_setup | 1 |
| | io_uring/io_uring.c | io_uring_try_cancel_iowq | 1 |
| | io_uring/io_uring.c | io_uring_try_cancel_requests | 3 |
| | io_uring/uring_cmd.c | io_uring_try_cancel_uring_cmd | 1 |
| | io_uring/tctx.c | io_uring_unreg_ringfd | 1 |
| | io_uring/io_uring.c | io_validate_ext_arg | 1 |
| | io_uring/waitid.c | io_waitid_remove_all | 1 |
| | io_uring/io-wq.c | io_wq_cancel_cb | 3 |
| | io_uring/io-wq.h | io_wq_current_is_worker | 1 |
| | io_uring/io-wq.c | io_wq_enqueue | 1 |
| | io_uring/io-wq.c | io_wq_exit_start | 1 |
| | io_uring/io-wq.c | io_wq_hash_work | 1 |
| | io_uring/io-wq.h | io_wq_is_hashed | 1 |
| | io_uring/io-wq.h | io_wq_put_hash | 1 |
| | io_uring/io-wq.c | io_wq_worker_stopped | 1 |
| | crypto/asymmetric_keys/x509_parser.h | IS_ERR | 2 |
| | block/blk-rq-qos.h | issue | 1 |
| | include/linux/slab.h | kfree | 10 |
| | include/linux/slab.h | kmalloc | 2 |
| | include/linux/slab.h | kmem_cache_alloc | 1 |
| | include/linux/slab.h | kmem_cache_alloc_bulk | 1 |
| | include/linux/slab.h | kmem_cache_create | 1 |
| | mm/slub.c | kmem_cache_free | 1 |
| | include/linux/ktime.h | ktime_add | 1 |
| | include/linux/ktime.h | ktime_add_ns | 1 |
| | include/linux/ktime.h | ktime_compare | 1 |
| | drivers/vdpa/mlx5/core/mr.c | kvfree | 2 |
| | include/linux/slab.h | kvmalloc_array | 1 |
| | include/linux/slab.h | kzalloc | 1 |
| | include/linux/compiler.h | likely | 6 |
| | drivers/gpu/drm/radeon/mkregtable.c | list_add_tail | 2 |
| | include/linux/list.h | list_cut_position | 1 |
| | include/linux/list.h | list_del | 1 |
| | include/linux/list.h | list_del_init | 2 |
| | drivers/net/wireless/ath/ath11k/hal.h | list_empty | 9 |
| | include/linux/list.h | list_empty_careful | 1 |
| | include/linux/list.h | list_first_entry | 4 |
| | drivers/gpu/drm/radeon/mkregtable.c | list_for_each_entry | 2 |
| | include/linux/list.h | list_for_each_entry_reverse | 1 |
| | include/linux/list.h | LIST_HEAD | 1 |
| | include/linux/list.h | list_rotate_left | 1 |
| | include/linux/llist.h | llist_add | 2 |
| | include/linux/llist.h | llist_del_all | 6 |
| | include/linux/llist.h | llist_empty | 1 |
| | include/linux/llist.h | llist_for_each_entry_safe | 1 |
| | lib/llist.c | llist_reverse_order | 2 |
| | include/linux/lockdep.h | lockdep_assert | 1 |
| | include/linux/lockdep.h | lockdep_assert_held | 5 |
| | include/linux/uidgid.h | make_kgid | 1 |
| | Documentation/scheduler/sched-pelt.c | max | 2 |
| | arch/alpha/include/asm/string.h | memcpy | 1 |
| | arch/alpha/include/asm/string.h | memset | 6 |
| | arch/arc/include/asm/arcregs.h | min | 4 |
| | arch/powerpc/boot/types.h | min_t | 1 |
| | include/linux/sched/mm.h | mmdrop | 1 |
| | include/linux/sched/mm.h | mmgrab | 1 |
| | drivers/block/aoe/aoenet.c | __must_hold | 11 |
| | include/linux/mutex.h | mutex_init | 2 |
| | include/linux/mutex.h | mutex_lock | 21 |
| | include/linux/mutex.h | mutex_unlock | 22 |
| | arch/arm64/include/asm/thread_info.h | need_resched | 4 |
| | include/linux/capability.h | ns_capable_noaudit | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | offsetof | 21 |
| | include/linux/cred.h | override_creds | 1 |
| | arch/powerpc/boot/page.h | PAGE_ALIGN | 2 |
| | include/linux/percpu_counter.h | percpu_counter_add | 1 |
| | include/linux/percpu_counter.h | percpu_counter_read_positive | 1 |
| | include/linux/percpu_counter.h | percpu_counter_sub | 2 |
| | include/linux/percpu_counter.h | percpu_counter_sum | 1 |
| | lib/percpu-refcount.c | percpu_ref_exit | 2 |
| | include/linux/percpu-refcount.h | percpu_ref_get | 4 |
| | include/linux/percpu-refcount.h | percpu_ref_get_many | 1 |
| | lib/percpu-refcount.c | percpu_ref_init | 1 |
| | include/linux/percpu-refcount.h | percpu_ref_kill | 1 |
| | include/linux/percpu-refcount.h | percpu_ref_put | 6 |
| | include/linux/percpu-refcount.h | percpu_ref_put_many | 1 |
| | drivers/gpu/drm/i915/i915_perf.c | poll_wait | 1 |
| | include/keys/asymmetric-parser.h | prep | 1 |
| | kernel/sched/wait.c | prepare_to_wait | 1 |
| | kernel/sched/wait.c | prepare_to_wait_exclusive | 1 |
| | include/linux/err.h | PTR_ERR | 2 |
| | include/linux/cred.h | put_cred | 3 |
| | include/linux/sched/task.h | put_task_struct | 2 |
| | include/linux/sched/task.h | put_task_struct_many | 1 |
| | drivers/scsi/bfa/bfad_im.h | queue_work | 1 |
| | include/linux/spinlock.h | raw_spin_lock_init | 1 |
| | include/linux/spinlock.h | raw_spin_lock_irq | 2 |
| | include/linux/spinlock.h | raw_spin_unlock_irq | 2 |
| | include/asm-generic/rwonce.h | READ_ONCE | 31 |
| | include/linux/refcount.h | refcount_add | 1 |
| | include/linux/sysctl.h | register_sysctl_init | 1 |
| | arch/parisc/kernel/firmware.c | __releases | 1 |
| | io_uring/io_uring.c | req_fail_link_node | 2 |
| | io_uring/io_uring.c | req_need_defer | 3 |
| | io_uring/refs.h | req_ref_get | 1 |
| | io_uring/refs.h | req_ref_put | 1 |
| | block/blk.h | req_ref_put_and_test | 1 |
| | io_uring/refs.h | req_ref_put_and_test_atomic | 1 |
| | io_uring/io_uring.h | req_set_fail | 2 |
| | include/linux/sched/signal.h | restore_saved_sigmask_unless | 1 |
| | include/linux/cred.h | revert_creds | 1 |
| | io_uring/io_uring.c | rings_size | 1 |
| | include/linux/log2.h | roundup_pow_of_two | 2 |
| | include/linux/sched/signal.h | same_thread_group | 1 |
| | drivers/firmware/efi/libstub/efistub.h | schedule | 3 |
| | include/linux/workqueue.h | schedule_delayed_work | 1 |
| | include/linux/security.h | security_uring_allowed | 1 |
| | include/linux/security.h | security_uring_override_creds | 1 |
| | arch/alpha/include/asm/bitops.h | set_bit | 2 |
| | kernel/signal.c | set_compat_user_sigmask | 1 |
| | include/linux/sched.h | __set_current_state | 3 |
| | include/linux/sched.h | set_current_state | 1 |
| | include/linux/sched/signal.h | __set_notify_signal | 1 |
| | kernel/signal.c | set_user_sigmask | 1 |
| | include/uapi/linux/stat.h | S_ISBLK | 1 |
| | include/uapi/linux/stat.h | S_ISREG | 1 |
| | include/linux/stddef.h | sizeof_field | 3 |
| | arch/arm64/include/asm/vdso/compat_barrier.h | smp_mb | 2 |
| | arch/arm64/include/asm/vdso/compat_barrier.h | smp_rmb | 1 |
| | include/asm-generic/barrier.h | smp_store_release | 1 |
| | drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.h | spin_lock | 12 |
| | include/linux/spinlock.h | spin_lock_init | 2 |
| | include/linux/spinlock.h | spin_unlock | 14 |
| | include/linux/jump_label.h | static_branch_dec | 1 |
| | include/linux/jump_label.h | static_branch_inc | 1 |
| | include/linux/jump_label.h | static_branch_unlikely | 1 |
| | drivers/gpu/drm/amd/display/include/vector.h | struct_size | 1 |
| | kernel/rcu/tiny.c | synchronize_rcu | 1 |
| | include/linux/sched/signal.h | task_sigpending | 3 |
| | kernel/task_work.c | task_work_add | 3 |
| | include/linux/task_work.h | task_work_pending | 2 |
| | io_uring/io_uring.c | tctx_inflight | 3 |
| | io_uring/io_uring.c | tctx_task_work_run | 1 |
| | arch/x86/boot/bitops.h | test_bit | 3 |
| | include/linux/jiffies.h | time_after | 2 |
| | include/linux/ktime.h | timespec64_to_ktime | 1 |
| | unknown | trace_io_uring_complete | 1 |
| | unknown | trace_io_uring_cqe_overflow | 1 |
| | unknown | trace_io_uring_cqring_wait | 1 |
| | unknown | trace_io_uring_create | 1 |
| | unknown | trace_io_uring_defer | 1 |
| | unknown | trace_io_uring_file_get | 1 |
| | unknown | trace_io_uring_link | 1 |
| | unknown | trace_io_uring_local_work_run | 1 |
| | unknown | trace_io_uring_queue_async_work | 1 |
| | unknown | trace_io_uring_req_failed | 1 |
| | unknown | trace_io_uring_submit_req | 1 |
| | unknown | trace_io_uring_task_work_run | 1 |
| | include/linux/atomic/atomic-instrumented.h | try_cmpxchg | 1 |
| | include/linux/kernel.h | u64_to_user_ptr | 3 |
| | include/linux/compiler.h | unlikely | 56 |
| | arch/arm64/include/asm/uaccess.h | unsafe_get_user | 4 |
| | arch/arm64/include/asm/uaccess.h | user_access_begin | 1 |
| | arch/arm64/include/asm/uaccess.h | user_access_end | 2 |
| | kernel/sched/completion.c | wait_for_completion_interruptible | 1 |
| | kernel/sched/completion.c | wait_for_completion_interruptible_timeout | 1 |
| | include/linux/wait.h | wake_up | 3 |
| | include/linux/wait.h | wake_up_all | 1 |
| | kernel/sched/core.c | wake_up_process | 1 |
| | kernel/sched/core.c | wake_up_state | 1 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 16 |
| | include/linux/wait.h | wq_has_sleeper | 1 |
| | io_uring/slist.h | wq_list_add_head | 1 |
| | io_uring/slist.h | wq_list_add_tail | 1 |
| | io_uring/slist.h | wq_list_empty | 7 |
| | io_uring/slist.h | __wq_list_for_each | 1 |
| | io_uring/slist.h | wq_stack_add_head | 1 |
| | include/asm-generic/rwonce.h | WRITE_ONCE | 9 |
| | lib/xarray.c | xa_destroy | 2 |
| | include/linux/xarray.h | xa_for_each | 3 |
| | include/linux/xarray.h | xa_init | 1 |
| | include/linux/xarray.h | xa_init_flags | 1 |
| | lib/xarray.c | xa_load | 1 |
io_uring.h | include/linux/atomic/atomic-instrumented.h | atomic_read | 1 |
| | include/linux/sched/signal.h | clear_notify_signal | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | container_of | 1 |
| | include/linux/poll.h | file_can_poll | 1 |
| | fs/file_table.c | fput | 1 |
| | include/linux/preempt.h | in_task | 1 |
| | io_uring/io_uring.c | __io_alloc_req_refill | 1 |
| | io_uring/alloc_cache.h | io_cache_alloc | 1 |
| | io_uring/io_uring.c | __io_commit_cqring_flush | 1 |
| | io_uring/io_uring.c | io_cqe_cache_refill | 1 |
| | io_uring/io_uring.h | io_extract_req | 1 |
| | io_uring/io_uring.h | io_get_cqe | 2 |
| | io_uring/io_uring.h | io_get_cqe_overflow | 1 |
| | io_uring/io_uring.h | io_local_work_pending | 2 |
| | io_uring/io_uring.h | io_lockdep_assert_cq_locked | 2 |
| | io_uring/io_uring.h | io_req_cache_empty | 1 |
| | io_uring/io_uring.h | io_req_set_res | 1 |
| | io_uring/io_uring.c | __io_req_task_work_add | 1 |
| | io_uring/io_uring.h | io_req_task_work_add | 1 |
| | io_uring/io_uring.c | __io_submit_flush_completions | 1 |
| | io_uring/io_uring.c | io_task_refs_refill | 1 |
| | arch/arm/include/asm/uaccess-asm.h | IS_ENABLED | 1 |
| | include/linux/slab.h | kmalloc | 1 |
| | kernel/time/timekeeping.c | ktime_get | 1 |
| | kernel/time/timekeeping.c | ktime_get_with_offset | 1 |
| | include/linux/compiler.h | likely | 2 |
| | include/linux/llist.h | llist_empty | 1 |
| | include/linux/lockdep.h | lockdep_assert | 2 |
| | include/linux/lockdep.h | lockdep_assert_held | 7 |
| | arch/alpha/include/asm/string.h | memcpy | 2 |
| | arch/alpha/include/asm/string.h | memset | 1 |
| | arch/arc/include/asm/arcregs.h | min | 1 |
| | drivers/block/aoe/aoenet.c | __must_hold | 1 |
| | include/linux/mutex.h | mutex_lock | 1 |
| | include/linux/mutex.h | mutex_unlock | 1 |
| | include/linux/percpu-refcount.h | percpu_ref_is_dying | 1 |
| | include/linux/wait.h | poll_to_key | 2 |
| | include/asm-generic/rwonce.h | READ_ONCE | 2 |
| | include/linux/resume_user_mode.h | resume_user_mode_work | 1 |
| | include/linux/sched.h | __set_current_state | 3 |
| | include/asm-generic/barrier.h | smp_load_acquire | 1 |
| | include/asm-generic/barrier.h | smp_store_release | 1 |
| | include/linux/task_work.h | task_work_pending | 2 |
| | kernel/task_work.c | task_work_run | 1 |
| | io_uring/io_uring.c | tctx_task_work_run | 1 |
| | arch/x86/boot/bitops.h | test_bit | 1 |
| | include/linux/thread_info.h | test_thread_flag | 2 |
| | unknown | trace_io_uring_complete | 1 |
| | unknown | trace_io_uring_complete_enabled | 1 |
| | include/linux/compiler.h | unlikely | 9 |
| | kernel/sched/wait.c | __wake_up | 2 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 1 |
| | include/linux/wait.h | wq_has_sleeper | 2 |
| | io_uring/slist.h | wq_list_add_tail | 1 |
| | io_uring/slist.h | wq_list_empty | 1 |
| | io_uring/slist.h | wq_stack_extract | 1 |
kbuf.c | arch/arm64/include/asm/uaccess.h | access_ok | 1 |
| | arch/mips/boot/tools/relocs.h | ARRAY_SIZE | 1 |
| | include/linux/overflow.h | check_add_overflow | 1 |
| | include/linux/overflow.h | check_mul_overflow | 1 |
| | include/linux/sched.h | cond_resched | 2 |
| | include/linux/uaccess.h | copy_from_user | 3 |
| | include/linux/uaccess.h | copy_to_user | 1 |
| | include/linux/overflow.h | flex_array_size | 1 |
| | drivers/gpu/drm/i915/i915_vma_resource.h | guard | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | INIT_LIST_HEAD | 2 |
| | io_uring/kbuf.c | io_add_buffers | 1 |
| | io_uring/kbuf.c | io_buffer_add_list | 2 |
| | io_uring/kbuf.c | io_buffer_get_list | 9 |
| | io_uring/memmap.c | io_create_region_mmap_safe | 1 |
| | io_uring/kbuf.c | io_destroy_bl | 1 |
| | io_uring/io_uring.h | io_file_can_poll | 1 |
| | io_uring/memmap.c | io_free_region | 2 |
| | io_uring/kbuf.c | io_kbuf_commit | 3 |
| | io_uring/kbuf.c | io_kbuf_drop_legacy | 1 |
| | io_uring/kbuf.c | io_kbuf_inc_commit | 1 |
| | include/linux/io_uring_types.h | io_kiocb_to_cmd | 4 |
| | io_uring/kbuf.c | io_provided_buffer_select | 2 |
| | io_uring/kbuf.c | io_provided_buffers_select | 2 |
| | io_uring/kbuf.c | io_put_bl | 3 |
| | io_uring/kbuf.c | __io_put_kbuf_ring | 1 |
| | io_uring/memmap.h | io_region_get_ptr | 1 |
| | io_uring/kbuf.c | __io_remove_buffers | 2 |
| | io_uring/io_uring.h | io_req_set_res | 2 |
| | io_uring/kbuf.c | io_ring_buffer_select | 1 |
| | io_uring/kbuf.c | io_ring_buffers_peek | 2 |
| | io_uring/kbuf.c | io_ring_head_to_buf | 4 |
| | io_uring/io_uring.h | io_ring_submit_lock | 5 |
| | io_uring/io_uring.h | io_ring_submit_unlock | 5 |
| | arch/microblaze/mm/pgtable.c | is_power_of_2 | 1 |
| | include/linux/slab.h | kfree | 6 |
| | include/linux/slab.h | kmalloc | 1 |
| | include/linux/slab.h | kmalloc_array | 1 |
| | include/linux/slab.h | kzalloc | 2 |
| | include/linux/compiler.h | likely | 1 |
| | include/linux/list.h | list_add | 1 |
| | drivers/gpu/drm/radeon/mkregtable.c | list_add_tail | 1 |
| | include/linux/list.h | list_del | 2 |
| | drivers/net/wireless/ath/ath11k/hal.h | list_empty | 4 |
| | include/linux/list.h | list_first_entry | 2 |
| | include/linux/lockdep.h | lockdep_assert_held | 6 |
| | arch/alpha/include/asm/string.h | memset | 2 |
| | include/linux/minmax.h | min_not_zero | 1 |
| | arch/powerpc/boot/types.h | min_t | 3 |
| | arch/powerpc/boot/page.h | PAGE_ALIGN | 1 |
| | include/asm-generic/rwonce.h | READ_ONCE | 8 |
| | io_uring/io_uring.h | req_set_fail | 2 |
| | include/linux/cleanup.h | scoped_guard | 3 |
| | include/asm-generic/barrier.h | smp_load_acquire | 2 |
| | include/linux/kernel.h | u64_to_user_ptr | 4 |
| | include/linux/compiler.h | unlikely | 11 |
| | include/asm-generic/bug.h | WARN_ON_ONCE | 2 |
| | lib/xarray.c | xa_erase | 3 |
| | include/linux/xarray.h | xa_err | 1 |
| | include/linux/xarray.h | xa_find | 1 |
| | lib/xarray.c | xa_load | 2 |
| | lib/xarray.c | xa_store | 1 |kbuf.h | io_uring/kbuf.c | io_kbuf_recycle_legacy | 1 |
| | io_uring/kbuf.h | io_kbuf_recycle_ring | 1 |
| | io_uring/kbuf.c | __io_put_kbufs | 2 |
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
| |	linux/io_uring_types.h | io_tw_token_t | 1
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
| | register.h | io_uring_register_get_file | 1
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
| | rsrc.c | io_unaccount_mem | 2


Continue with the list untill all functions used in each source are listed.