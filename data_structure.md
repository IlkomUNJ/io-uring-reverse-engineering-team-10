# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
| | | | | | | | 
io_mapped_region | io_uring/memmap.h  | struct page **pages, void *ptr, unsigned int nr_pages, unsigned int flags | io_free_region | memmap.c | function parameter (mr)
| | | | io_region_init_ptr | memmap.c | function parameter (mr)
| | | | io_region_pin_pages | memmap.c | function parameter (mr)
| | | | io_region_allocate_pages | memmap.c | function parameter (mr)
| | | | io_create_region | memmap.c | function parameter (mr)
| | | | io_create_region_mmap_safe | memmap.c | local variable (tmp_mr), function parameter (mr)
| | | | io_mmap_get_region | memmap.c | return value
| | | | io_region_validate_mmap | memmap.c | function parameter (mr)
| | | | io_region_mmap | memmap.c | function parameter (mr)
io_imu_folio_data | io_uring/memmap.h | (struct definition not visible in snippet) | io_check_coalesce_buffer | memmap.c | local variable (ifd)
io_uring_region_desc | io_uring_types.h | __u64 user_addr, __u64 size, __u32 flags, __u32 mmap_offset, __u32 id, __u32 __resv[2] | io_region_pin_pages | memmap.c | function parameter (reg)
| | | | io_region_allocate_pages | memmap.c | function parameter (reg)
| | | | io_create_region | memmap.c | function parameter (reg)
| | | | io_create_region_mmap_safe | memmap.c | function parameter (reg)
io_mapped_region | io_uring/memmap.h | struct page **pages, void *ptr, unsigned int nr_pages, unsigned int flags | io_free_region | memmap.h | function parameter (mr)
| | | | io_create_region | memmap.h | function parameter (mr)
| | | | io_create_region_mmap_safe | memmap.h | function parameter (mr)
| | | | io_region_get_ptr | memmap.h | function parameter (mr)
| | | | io_region_is_set | memmap.h | function parameter (mr)
io_uring_region_desc | io_uring_types.h | __u64 user_addr, __u64 size, __u32 flags, __u32 mmap_offset, __u32 id | io_create_region | memmap.h | function parameter (reg)
| | | | io_create_region_mmap_safe | memmap.h | function parameter (reg)
io_ring_ctx | io_uring_types.h | struct io_mapped_region ring_region, struct io_user *user, etc. | io_free_region | memmap.h | function parameter (ctx)
| | | | io_create_region | memmap.h | function parameter (ctx)
| | | | io_create_region_mmap_safe | memmap.h | function parameter (ctx)
io_msg | msg_ring.c | struct file *file, *src_file, struct callback_head tw, u64 user_data, u32 len, cmd, src_fd, dst_fd/cqe_flags, flags | io_msg_ring_cleanup | msg_ring.c | Accesses msg->src_file for cleanup with fput()
| | | | io_msg_tw_complete | msg_ring.c | Converts from callback_head using container_of()
| | | | io_msg_data_remote | msg_ring.c | Reads msg->flags and msg->user_data for remote posting
| | | | io_msg_ring_data | msg_ring.c | Main parameter for data ring operations
| | | | io_msg_grab_file | msg_ring.c | Populates msg->src_file from file table
| | | | io_msg_install_complete | msg_ring.c | Uses msg->dst_fd for FD installation
io_ring_ctx | io_uring_types.h | struct mutex uring_lock,struct io_alloc_cache msg_cache, spinlock_t msg_lock, bool task_complete | io_double_unlock_ctx | msg_ring.c | Releases octx->uring_lock mutex
| | | | io_lock_external_ctx | msg_ring.c | Acquires target context's uring_lock
| | | | io_msg_need_remote | msg_ring.c | Checks ctx->task_complete for remote execution need
| | | | io_msg_get_kiocb | msg_ring.c | Accesses ctx->msg_cache with msg_lock protection
io_kiocb | io_uring_types.h | struct io_ring_ctx *ctx, struct io_tw_task_work io_task_work, u64 user_data | io_msg_tw_complete | msg_ring.c | Processes completion via req->cqe
| | | | io_msg_remote_post | msg_ring.c | Configures req->opcode as IORING_OP_NOP for remote completion
io_uring_sqe | uapi/linux/io_uring.h | off, len, addr, addr3, file_index, msg_ring_flags | io_uring_sync_msg_ring | msg_ring.h | Reads SQE fields for synchronous message ring operations
| | | | io_msg_ring_prep | msg_ring.h | Validates and prepares SQE fields for async message ring
io_kiocb | io_uring_types.h | ctx, flags | io_msg_ring_prep | msg_ring.h | Receives prepared request structure
| | | | io_msg_ring | msg_ring.h | Main parameter for message ring operations
| | | | io_msg_ring_cleanup | msg_ring.h | Cleans up request resources
io_napi_entry | napi.c | unsigned int napi_id, struct list_head list, unsigned long timeout, struct hlist_node node, struct rcu_head rcu | io_napi_hash_find | napi.c | Finds entry by napi_id in hash table
| | | | __io_napi_add_id | napi.c | Creates and inserts new entry
| | | | __io_napi_del_id | napi.c | Removes and frees entry
| | | | __io_napi_remove_stale | napi.c | Cleans up stale entries based on timeout
io_ring_ctx | io_uring_types.h | struct hlist_head *napi_ht, spinlock_t napi_lock, struct list_head napi_list, bool napi_prefer_busy_poll, ktime_t napi_busy_poll_dt, int napi_track_mode | io_napi_init | napi.c | Initializes napi tracking structures
| | | | io_napi_free | napi.c | Cleans up all napi entries
| | | | io_napi_register_napi | napi.c | Configures napi tracking mode and params
| | | | __io_napi_busy_loop | napi.c | Executes busy polling loop
io_uring_napi | uapi/linux/io_uring.h | __u64 busy_poll_to, __u8 prefer_busy_poll, __u8 opcode, __u16 op_param, __u32 pad[2], __u32 resv | io_register_napi | napi.c | User API structure for napi configuration
| | | | io_unregister_napi | napi.c | Clears napi configuration
io_wait_queue | io_uring.h | ktime_t timeout, ktime_t napi_busy_poll_dt, bool napi_prefer_busy_poll | io_napi_blocking_busy_loop | napi.c | Contains parameters for blocking busy loop
io_ring_ctx | io_uring_types.h | struct list_head napi_list, int napi_track_mode | io_napi_init() | napi.c | Context structure containing NAPI tracking state
io_wait_queue | io_uring.h | ktime_t timeout, ktime_t napi_busy_poll_dt | io_napi_busy_loop() | napi.c | Wait queue structure for blocking operations
io_kiocb | io_uring_types.h | struct io_ring_ctx *ctx, struct file *file | io_napi_add() | napi.c | I/O request structure
io_shutdown | net.c | struct file *file, int how | io_shutdown_prep | net.c | Validates shutdown parameters
| | | | io_shutdown | net.c | Executes socket shutdown operation
io_accept | net.c | struct file *file, struct sockaddr __user *addr, int __user *addr_len, int flags, int iou_flags, u32 file_slot, unsigned long nofile | io_accept_prep | net.c | Prepares accept operation parameters
| | | | io_accept | net.c | Handles socket accept operations
io_socket | net.c | struct file *file, int domain, int type, int protocol, int flags, u32 file_slot, unsigned long nofile  |  io_socket_prep | net.c | Validates socket creation parameters
| | | | io_socket | net.c | Creates new socket
io_connect | net.c | struct file *file, struct sockaddr __user *addr, int addr_len, bool in_progress, bool seen_econnaborted | io_connect_prep | net.c | Prepares connection parameters
| | | | io_connect | net.c | Handles socket connection
io_bind | net.c | struct file *file, int addr_len | io_bind_prep | net.c | Validates bind parameters
| | | | io_bind | net.c | Binds socket to address
io_listen | net.c | struct file *file, int backlog | io_listen_prep | net.c | Validates listen parameters
| | | | io_listen | net.c | Starts listening on socket
io_sr_msg | net.c | struct file *file, union {compat_msghdr/umsg/buf}, int len, unsigned done_io, unsigned msg_flags, u16 flags, u16, buf_group, bool retry, void __user *msg_control, struct io_kiocb *notif | io_sendmsg_prep | net.c | Prepares send/recv message parameters
| | | | io_recvmsg_prep | net.c | Prepares receive message parameters
| | | | io_send | net.c | Handles socket send operation
| | | | io_recv | net.c | Handles socket receive operation
io_recvzc | net.c | struct file *file, unsigned msg_flags, u16 flags, u32 len, struct io_zcrx_ifq *ifq | io_recvzc_prep | net.c | Prepares zero-copy receive parameters
| | | | io_recvzc | net.c | Handles zero-copy receive
io_async_msghdr | io_uring.h | struct iovec fast_iov, struct io_vec vec, struct msghdr msg, struct sockaddr_storage addr, size_t payloadlen, unsigned namelen, unsigned controllen | io_msg_alloc_async | net.c | Allocates async message header
| | | | io_netmsg_recycle | net.c | Recycles async message buffers
| | | | io_sendmsg_setup | net.c | Sets up sendmsg operation
| | | | io_recvmsg_copy_hdr | net.c | Copies message header
proto_accept_arg | net.c | int err, int is_empty, int flags | io_accept | net.c | Tracks accept operation state
buf_sel_arg | net.c | struct iovec *iovs, int nr_iovs, size_t max_len, int mode, size_t out_len | io_send_select_buffer | net.c | Manages buffer selection for I/O
| | | | io_recv_buf_select | net.c | Selects receive buffers
io_recvmsg_multishot_hdr | net.c | struct io_uring_recvmsg_out msg, struct sockaddr_storage addr | io_recvmsg_multishot | net.c | Stores multishot receive header data
io_async_msghdr | net.h | struct iou_vec vec, struct iovec fast_iov, struct msghdr msg, struct sockaddr_storage addr, size_t payloadlen/controllen, struct sockaddr __user *uaddr | io_sendmsg_prep() | net.h | Async message header for network operations
io_nop | nop.c | struct file *file, int result, int fd, unsigned int flags | io_nop_prep() | nop.c | No-operation request structure
io_notif_data | notif.c | struct ubuf_info uarg, bool zc_report/zc_used/zc_copied, unsigned account_pages, struct io_notif_data next/head | io_alloc_notif() | notif.c  | Notification tracking structure
io_notif_data | notif.h | struct file *file, struct ubuf_info uarg, struct io_notif_data next/head, unsigned account_pages, bool zc_report/zc_used/zc_copied | io_alloc_notif | notif.c | Tracks zero-copy notification state
| | | | io_tx_ubuf_complete | notif.c | Contains completion callback data
| | | | io_notif_flush | notif.h | Stores memory accounting information
io_kiocb | io_uring_types.h | struct io_ring_ctx *ctx, struct io_tw_task_work io_task_work | io_alloc_notif | notif.h | Base structure for notification requests
ubuf_info | linux/skbuff.h | void (*complete)(...), unsigned long flags, refcount_t refcnt | io_tx_ubuf_complete | notif.h | Kernel's universal buffer info structure
io_issue_def | opdef.h | unsigned needs_file:1, unsigned plug:1, unsigned ioprio:1, unsigned iopoll:1, unsigned buffer_select:1, unsigned hash_reg_file:1, unsigned unbound_nonreg_file:1, unsigned pollin:1, unsigned pollout:1, unsigned poll_exclusive:1, unsigned audit_skip:1, unsigned iopoll_queue:1, unsigned vectored:1, unsigned short async_size, int (*issue)(struct io_kiocb , unsigned int), int (prep)(struct io_kiocb *, const struct io_uring_sqe *) | io_uring core | opdef.c | Defines per-opcode execution properties and handlers
io_cold_def | opdef.h | const char name, void (cleanup)(struct io_kiocb ), void (fail)(struct io_kiocb *) | io_uring core | opdef.c | Contains cold path operation handlers and metadata
io_open | openclose.c | struct file *file, int dfd, u32 file_slot, struct filename *filename, struct open_how how, unsigned long nofile	| io_openat_prep | openclose.c | Stores open operation parameters
| | | | io_openat2_prep | openclose.c | Handles both regular and openat2-style opens
| | | | io_openat | openclose.c | Manages file descriptor allocation
io_close | openclose.c | struct file *file, int fd, u32 file_slot | io_close_prep | openclose.c | Tracks close operation state
| | | | io_close | openclose.c | Handles both regular and fixed file closes
io_fixed_install | openclose.c | struct file *file, unsigned int, o_flags | io_install_fixed_fd_prep | openclose.c | Manages fixed file descriptor installation
| | | | io_install_fixed_fd | openclose.c | Validates and processes fd installation flags
io_poll	| poll.h | struct file *file, struct wait_queue_head *head, __poll_t events, int retries, struct wait_queue_entry wait | io_poll_add | poll.h | Tracks poll operation state
async_poll | poll.h	| struct io_poll poll, struct io_poll, *double_poll | io_arm_poll_handler | poll.h | Handles async poll operations
io_poll_update | poll.c | struct file *file, u64 old_user_data, u64 new_user_data, __poll_t events, bool update_events, bool update_user_data | io_poll_remove | poll.c | Handles updates to existing poll requests (event flags/user_data)
io_poll_table | poll.c | struct poll_table_struct pt, struct io_kiocb *req, int nr_entries, int error, bool owning, __poll_t result_mask | io_arm_poll_handler | poll.c | Tracks state during poll arm/wake operations
| | | | __io_arm_poll_handler | poll.c | Tracks state during poll arm/wake operations
io_poll | poll.c | struct wait_queue_head *head, struct wait_queue_entry wait, __poll_t events, int retries (for async_poll) | io_poll_wake | poll.c | Core poll request tracking structure
| | | | io_poll_add | poll.c | Core poll request tracking structure
| | | | io_poll_remove_entries | poll.c | Core poll request tracking structure
async_poll | poll.c | struct io_poll poll, struct io_poll *double_poll | io_async_queue_proc | poll.c | Extended poll data for async operations
| | | | io_req_alloc_apoll | poll.c | Extended poll data for async operations
io_uring_probe | register.c | __u32 last_op, __u32 ops_len, struct io_uring_probe_op ops[] | io_probe | io_uring.c | Reports supported opcodes
io_restriction | register.c | unsigned long register_op[], unsigned long sqe_op[], __u32 sqe_flags_allowed, __u32 sqe_flags_required, bool registered | io_register_restrictions | io_uring.c | Tracks operation restrictions
io_ring_ctx_rings | register.c | struct io_rings *rings, struct io_uring_sqe *sq_sqes, struct io_mapped_region sq_region, struct io_mapped_region ring_region | io_register_resize_rings | register.c | Temporary storage during ring resizing
io_uring_clock_register | register.c | __s32 clockid, __u64 __resv[3] | io_register_clock | io_uring.c | Configures clock source
io_uring_mem_region_reg | register.c | __u64 region_uptr, __u32 flags, __u32 __resv[3] | io_register_mem_region | io_uring.c | Memory region registration
io_rsrc_node | rsrc.c | int type, refcount_t refs, u64 tag, union { struct file *file; struct io_mapped_ubuf *buf; } | io_rsrc_node_alloc | rsrc.c | Tracks individual registered resources
| | | | io_free_rsrc_node | rsrc.c | Tracks individual registered resources
io_mapped_ubuf | rsrc.c | unsigned long ubuf, size_t len, struct bio_vec bvec[], refcount_t refs | io_buffer_unmap | rsrc.c | Manages pinned user buffers
| | | | io_sqe_buffer_register | rsrc.c | Manages pinned user buffers
io_rsrc_data | rsrc.c | unsigned nr, struct io_rsrc_node **nodes | io_rsrc_data_alloc | rsrc.c | Contains array of resource nodes
| | | | io_rsrc_data_free | rsrc.c | Contains array of resource nodes
io_uring_rsrc_update2 | rsrc.c | __u64 data, __u64 tags, __u32 nr, __u32 offset | __io_register_rsrc_update | io_uring.c | Update operation parameters
io_uring_clone_buffers | rsrc.c | __s32 src_fd, __u32 src_off, __u32 dst_off | io_register_clone_buffers | io_uring.c | Buffer cloning parameters
io_rsrc_node | rsrc.h | type (file/buffer), refs (refcount), tag (user tag), union { file_ptr, buf } | io_rsrc_node_alloc | rsrc.c | Tracks single registered resource (file/buffer)
| | | | io_free_rsrc_node | rsrc.c | Tracks single registered resource (file/buffer)
io_mapped_ubuf | rsrc.h | ubuf (user addr), len (buffer size), nr_bvecs, folio_shift, refs, acct_pages, is_kbuf, dir (IO_IMU_*), bvec[] | io_sqe_buffer_register | rsrc.c | Manages pinned user/kernel buffers
| | | | io_buffer_unmap | rsrc.c | Manages pinned user/kernel buffers
io_imu_folio_data | rsrc.h | nr_pages_head, nr_pages_mid, folio_shift, nr_folios | io_check_coalesce_buffer | rsrc.c | Tracks compound page info for buffer coalescing


io_rw       | io_uring/rw.c | struct kiocb, u64 addr, u32 len, rwf_t flags  | io_iov_compact_buffer_select_prep | io_uring/rw.c | function parameter
| | | | io_iov_buffer_select_prep | io_uring/rw.c | local variable, function parameter
| | | | __io_import_iovec | io_uring/rw.c | local variable, function parameter
| | | | io_prep_rw_pi | io_uring/rw.c | function parameter
| | | | io_prep_rw | io_uring/rw.c | local variable, function parameter
| | | | io_prep_rw_fixed | io_uring/rw.c | local variable, function parameter
| | | | io_read_mshot_prep | io_uring/rw.c | local variable, function parameter
| | | | loff_t | io_uring/rw.c | local variable, function parameter
| | | | io_rw_should_reissue | io_uring/rw.c | local variable, function parameter
| | | | io_req_end_write | io_uring/rw.c | local variable, function parameter
| | | | io_req_io_end | io_uring/rw.c | local variable, function parameter
| | | | io_req_rw_complete | io_uring/rw.c | local variable, function parameter
| | | | io_complete_rw | io_uring/rw.c | local variable, function parameter
| | | | io_complete_rw_iopoll | io_uring/rw.c | local variable, function parameter
| | | | io_rw_done | io_uring/rw.c | local variable, function parameter
| | | | kiocb_done | io_uring/rw.c | local variable, function parameter
| | | | loop_rw_iter | io_uring/rw.c | function parameter
| | | | io_async_buf_func | io_uring/rw.c | local variable, function parameter
| | | | io_rw_should_retry | io_uring/rw.c | local variable, function parameter
| | | | io_iter_do_read | io_uring/rw.c | function parameter
| | | | io_rw_init_file | io_uring/rw.c | local variable, function parameter
| | | | __io_read | io_uring/rw.c | local variable, function parameter
| | | | io_read_mshot | io_uring/rw.c | local variable, function parameter
| | | | io_write | io_uring/rw.c | local variable, function parameter
| | | | io_uring_classic_poll | io_uring/rw.c | local variable, function parameter
---
io_meta_state   | io_uring/rw.h | u32 seed, struct iov_iter_state iter_meta | struct io_async_rw | io_uring/rw.h | local variable
io_async_rw   | io_uring/rw.h | size_t bytes_done, struct iovec *free_iovec, struct iov_iter iter, struct iov_iter_state iter_state, struct iovec fast_iov, int free_iov_nr, struct wait_page_queue wpq, struct uio_meta meta, struct io_meta_state meta_state | __cold | io_uring/io_uring.c | function parameter
| | | | struct io_issue_def | io_uring/opdef.c | function parameter
| | | | __io_import_iovec | io_uring/rw.c | function parameter
| | | | io_import_iovec | io_uring/rw.c | function parameter
| | | | io_rw_recycle | io_uring/rw.c | local variable


If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.
