# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

## another source
### alloc_cache.c
Fungsi-fungsi dalam file ini mengelola cache memori untuk objek I/O. io_alloc_cache_init menginisialisasi cache untuk menyimpan objek-objek memori, menentukan jumlah maksimum, ukuran objek, dan byte yang perlu dibersihkan. io_alloc_cache_free membersihkan cache dengan membebaskan objek-objek yang disimpan dan menghapus array cache. Sedangkan io_cache_alloc_new mengalokasikan objek baru, membersihkan sebagian objek jika diperlukan, dan mengembalikannya untuk digunakan. Fungsi-fungsi ini membantu mengoptimalkan alokasi dan pembebasan memori, meningkatkan performa sistem dengan mengurangi overhead alokasi berulang.

### cancel.c
File ini berisi fungsi-fungsi untuk menangani pembatalan permintaan I/O dalam sistem io_uring. Fungsi utama seperti io_cancel_req_match memeriksa kecocokan permintaan dengan kriteria pembatalan, io_async_cancel dan io_sync_cancel menangani pembatalan asinkron dan sinkron, sedangkan io_cancel_remove_all dan io_cancel_remove menghapus permintaan dari daftar yang relevan. Flag pembatalan digunakan untuk menentukan kriteria seperti berdasarkan file descriptor atau opcode. Fungsi-fungsi ini memastikan pembatalan I/O dilakukan dengan cara yang efisien dan sesuai kondisi yang diinginkan.

### epoll.c
File ini menangani operasi epoll dalam konteks io_uring di Linux. Fungsi utamanya adalah io_epoll_ctl_prep untuk mempersiapkan operasi epoll (menambah/menghapus file descriptor), io_epoll_ctl untuk mengeksekusi operasi tersebut, io_epoll_wait_prep untuk mempersiapkan penanganan event epoll, dan io_epoll_wait untuk menunggu dan mengembalikan event epoll yang terjadi. Semua operasi ini dilakukan secara asinkron untuk efisiensi I/O.

### eventfd.c
Fungsi-fungsi dalam file ini mengelola objek eventfd dalam konteks io_uring. Fungsi utama termasuk mendaftarkan dan membatalkan pendaftaran eventfd, memicu sinyal pada eventfd ketika terjadi event, serta menangani pengelolaan referensi dan pembebasan memori untuk objek io_ev_fd. Fungsi-fungsi ini memungkinkan pengelolaan notifikasi berbasis eventfd untuk meningkatkan efisiensi I/O asinkron dalam io_uring.

### fdinfo.c
Fungsi-fungsi dalam file ini digunakan untuk menampilkan informasi diagnostik terkait status dan konfigurasi io_uring. Fungsi io_uring_show_cred menampilkan kredensial pengguna, sementara common_tracking_show_fdinfo dan napi_show_fdinfo menampilkan informasi terkait polling NAPI. Fungsi utama, io_uring_show_fdinfo, menyajikan detail tentang antrian Submission Queue (SQE) dan Completion Queue (CQE), thread polling (jika ada), serta file dan buffer yang digunakan. Fungsi ini juga melaporkan status entri yang dibatalkan dan overflow dalam Completion Queue, membantu dalam pemantauan dan diagnosa sistem io_uring.

### filetable.c
File ini bertanggung jawab untuk mengelola alokasi dan pengelolaan file descriptor dalam konteks io_uring di Linux. Fungsi io_file_bitmap_get digunakan untuk mencari slot kosong dalam bitmap yang tersedia untuk alokasi file descriptor. io_alloc_file_tables mengalokasikan tabel file dan bitmap untuk mencatat file descriptor, sementara io_free_file_tables membebaskan keduanya setelah tidak digunakan. Fungsi io_install_fixed_file menginstal file descriptor tetap pada tabel file, dan __io_fixed_fd_install menginstal file descriptor tetap dengan memilih slot yang tepat. Fungsi io_fixed_fd_install merupakan fungsi utama untuk menginstal file descriptor tetap dengan mengunci dan membuka tabel file. io_fixed_fd_remove digunakan untuk menghapus file descriptor tetap dari tabel, dan io_register_file_alloc_range mengatur rentang alokasi untuk file descriptor. Secara keseluruhan, file ini menyediakan mekanisme efisien untuk pengelolaan file descriptor dalam io_uring.

### fs.c
File ini berisi fungsi-fungsi untuk menangani operasi sistem file secara asinkron menggunakan io_uring. Fungsi io_renameat_prep, io_unlinkat_prep, io_mkdirat_prep, io_symlinkat_prep, dan io_linkat_prep mempersiapkan parameter untuk operasi seperti mengganti nama, menghapus, membuat direktori, membuat symlink, dan membuat hard link. Setiap fungsi prep memeriksa dan memvalidasi input, kemudian menyimpan informasi yang diperlukan. Fungsi terkait (io_renameat, io_unlinkat, io_mkdirat, io_symlinkat, io_linkat) menjalankan operasi yang sesuai, sedangkan fungsi cleanup (io_renameat_cleanup, io_unlinkat_cleanup) membersihkan sumber daya yang digunakan setelah operasi selesai. Semua operasi ini dilakukan secara asinkron menggunakan io_uring untuk efisiensi I/O.

### futex.c
File ini berisi implementasi fungsi-fungsi untuk mengelola operasi futex asinkron dalam konteks io_uring. Fungsi-fungsi utama meliputi persiapan dan pembatalan operasi futex, seperti io_futex_prep untuk menyiapkan data futex, io_futex_wait dan io_futex_wake untuk menangani operasi menunggu dan membangunkan futex, serta io_futex_complete untuk menyelesaikan permintaan I/O setelah operasi futex. Selain itu, ada pengelolaan cache dan pembatalan operasi futex yang sedang berlangsung dengan io_futex_cache_init dan io_futex_cancel. Semua ini dilakukan dengan penguncian yang tepat untuk menjaga konsistensi dan efisiensi operasi.

### io_uring.c
File ini adalah implementasi utama dari subsistem io_uring dalam kernel Linux. File ini menangani logika tingkat rendah untuk menangani antrian permintaan I/O (submission queue) dan antrian penyelesaian (completion queue) antara aplikasi pengguna dan kernel, guna memungkinkan operasi I/O yang efisien dan asinkron. Di dalamnya terdapat berbagai fungsi dan struktur data yang bertugas untuk mengatur alokasi konteks io_ring_ctx, manajemen request (io_kiocb), manajemen sumber daya (file, buffer, futex, dll), serta mekanisme task work dan wakeup. File ini juga mencakup dukungan untuk polling, timeouts, penyusunan kembali request, serta pengelolaan dan pembersihan permintaan yang gagal atau tertunda. Selain itu, io_uring.c juga menangani interaksi dengan subsistem lainnya seperti futex, net, dan poll, dan menyertakan logika untuk menangani konfigurasi khusus seperti SQPOLL, IOPOLL, dan DEFER_TASKRUN. Fungsi-fungsi seperti io_issue_sqe, io_req_task_work_add, io_cqring_event_overflow, dan io_ring_ctx_alloc adalah bagian penting dari mekanisme kerja subsistem ini, yang memastikan permintaan I/O diproses, dijadwalkan, dan diselesaikan dengan benar di antara thread pengguna dan kernel.

### io-wq.c
File ini mengelola thread pool untuk menjalankan operasi I/O secara asynchronous dalam sistem io_uring. Fungsinya mencakup membuat workqueue (io_wq_create()), menambahkan pekerjaan (io_wq_enqueue()), menjalankan pekerjaan lewat worker (io_wq_worker()), serta mengatur jumlah dan siklus hidup worker thread (create_io_worker(), io_worker_exit()). Ia juga menangani pembatalan pekerjaan (io_wq_cancel_cb()), dan menyesuaikan afinitas CPU saat CPU online/offline. Semua ini bertujuan agar I/O blocking bisa dijalankan secara efisien di background, tanpa menghambat thread utama.

### kbuf.c
File ini mengelola penggunaan dan manajemen buffer dalam `io_uring`, termasuk penyediaan, pemilihan, daur ulang, dan penghapusan buffer. Buffer bisa disediakan secara manual oleh aplikasi (`io_provide_buffers`) atau melalui buffer ring (`io_register_pbuf_ring`) yang di-*mmap* ke userspace. Kernel akan memilih buffer saat operasi I/O dilakukan (`io_buffer_select`), dan setelahnya buffer bisa dikembalikan untuk digunakan ulang. Semua ini bertujuan untuk efisiensi dan menghindari alokasi memori berulang saat melakukan operasi I/O berkecepatan tinggi.

### memmap.c
Mengelola pemetaan memori antara ruang pengguna dan kernel untuk berbagai region memory yang digunakan oleh io_uring, seperti ring buffer dan buffer pool. File ini menangani fungsi seperti io_pin_pages() dan io_region_allocate_pages() untuk memetakan alamat pengguna ke halaman kernel atau mengalokasikan memory kernel. Proses ini dilakukan dengan memastikan keamanan (seperti overflow check) dan efisiensi akses memori bersama. Perbaikan terkait overflow dan validasi parameter diterapkan khususnya di fungsi io_pin_pages() untuk mencegah kondisi unsafe saat pinning user pages.

### msg_ring.c
Menangani mekanisme komunikasi antar io_uring context melalui perintah `IORING_MSG_DATA` untuk mengirim data dan `IORING_MSG_SEND_FD` untuk mentransfer file descriptor antar ring. File ini mencakup proses parsing pesan, validasi flag, penguncian context target, serta penjadwalan task secara asinkron menggunakan `task_work`. Serta mengelola alokasi dan cleanup request melalui cache internal, serta menangani error seperti context mati atau permintaan yang tidak valid. Fungsionalitas ini memungkinkan integrasi dan koordinasi antar ring secara efisien dalam sistem I/O asinkron `io_uring`.

### napi.c
Mengelola integrasi busy-polling NAPI dalam `io_uring`, termasuk registrasi, penghapusan, dan eksekusi loop polling untuk mengurangi latensi I/O. File ini menangani registrasi, penghapusan, dan manajemen entri NAPI, mendukung mode pelacakan statis dan dinamis, serta melakukan pembersihan otomatis terhadap entri yang tidak lagi aktif.

### net.c
Menangani integrasi jaringan dengan io_uring, termasuk logika untuk submit dan completion operasi socket, pengelolaan multishot receive, serta dukungan terhadap fitur seperti buffer selection dan zero-copy. File ini juga mencakup validasi dan pemrosesan opcode I/O jaringan untuk efisiensi dan kompatibilitas kernel.

### nop.c
Mengimplementasikan operasi NOP (no-operation) untuk io_uring, memungkinkan pengujian dan simulasi jalur I/O tanpa melakukan aksi I/O nyata. Ia mendukung berbagai flag seperti injeksi hasil, penggunaan file descriptor, dan buffer tetap, serta memvalidasi input untuk memastikan operasi NOP berjalan sesuai konfigurasi pengguna.

### notif.c
Menangani implementasi notifikasi zero-copy (zc) untuk operasi jaringan dalam io_uring. Ia mengelola siklus hidup buffer pengguna (ubuf_info) dan struktur terkait seperti io_notif_data, mendukung penyelesaian bertahap dan pengelompokan notifikasi. File ini juga mengatur akuntansi memori serta integrasi dengan mekanisme task_work, memastikan penyelesaian yang efisien dan sinkron untuk skenario I/O jaringan non-blok dan zero-copy.

### opdef.c
bBrfungsi sebagai tempat definisi dan pendaftaran operasi-oprasi (opcode) yang didukung oleh io_uring. File ini biasanya mengaitkan setiap kode operasi (IORING_OP_*) dengan fungsi-fungsi handler seperti fungsi inisialisasi, validasi, eksekusi, dan pembatalan jika tersedia. Ini memungkinkan io_uring mengenali dan menjalankan berbagai jenis permintaan I/O secara terstruktur dan modular.

### openclose.c
Mengimplementasikan operasi pembukaan dan penutupan file untuk io_uring, meliputi io_openat/io_openat2 dengan parsing SQE, validasi flag (O_PATH, O_LARGEFILE, O_NONBLOCK, O_CLOEXEC), alokasi FD baru atau penggunaan slot fixed, serta pembersihan sumber daya; dan io_close yang menangani penutupan FD biasa dan fixed, termasuk sinkronisasi dengan file_lock, penanganan metode flush, dan instalasi FD tetap (io_install_fixed_fd) sesuai flag pengguna.

### poll.c
Mengimplementasikan *async polling* di io_uring, mengubah operasi poll/epoll menjadi notifikasi via *Completion Queue (CQE)*. File ini menangani registrasi *fd*, monitoring event (seperti `EPOLLIN`), dan mengirim hasilnya secara asinkron, dengan optimasi seperti *batching* untuk kinerja tinggi.

### register.c
menangani pendaftaran (registration) sumber daya seperti file descriptor, buffer, atau eventfd ke dalam konteks io_uring untuk digunakan berulang dalam operasi I/O asinkron, mengurangi overhead sistem call dengan menyimpan resource di kernel (misal via io_uring_register_files() atau io_uring_register_buffers()), serta mengoptimasi kinerja melalui caching dan mengurangi locking.

### rsrc.c
Mengelola sumber daya (resources) seperti buffer dan file descriptor yang terdaftar, termasuk alokasi, pemantauan, dan pembersihan ketika tidak digunakan. File ini memastikan efisiensi dengan mekanisme caching dan reuse resource, serta menangani kasus seperti update atau pelepasan resource secara aman tanpa race condition.

### rw.c

### splice.c

### sqpoll.c

### statx.c

### sync.c

### tctx.c

### timeout.c

### truncate.c

### uring_cmd.c

### waitid.c

### xattr.c

### zcrx.c


## Headers
Just declare the function specification. 

### advice.h
File ini berisi deklarasi fungsi-fungsi yang terkait dengan penanganan operasi madvise dan fadvise dalam konteks io_uring. Operasi ini memungkinkan aplikasi memberikan petunjuk atau saran ke kernel agar bisa mengoptimalkan pengelolaan memori dan file, yang penting untuk performa tinggi dalam sistem besar atau beban kerja I/O berat.

### alloc_cache.h
Fungsi-fungsi dalam file ini mengelola cache memori untuk objek I/O di kernel. io_alloc_cache_init menginisialisasi cache, io_alloc_cache_free membersihkan cache dan membebaskan objek-objeknya. io_cache_alloc_new mengalokasikan objek baru jika cache kosong, sementara io_alloc_cache_put dan io_alloc_cache_get digunakan untuk menyimpan dan mengambil objek dari cache. io_cache_alloc mencoba mengambil objek dari cache, dan jika tidak ada, mengalokasikan objek baru. Terakhir, io_cache_free mengembalikan objek ke cache atau membebaskannya jika cache penuh. Fungsi-fungsi ini membantu mengoptimalkan penggunaan memori dengan mengurangi alokasi berulang.

### cancel.h
Fungsi-fungsi dalam file ini mengelola pembatalan operasi I/O di io_uring. io_async_cancel_prep mempersiapkan pembatalan, sedangkan io_async_cancel mengeksekusinya. io_try_cancel berusaha membatalkan operasi yang sedang berjalan, dan io_sync_cancel membatalkan secara sinkron. io_cancel_req_match memeriksa kesesuaian permintaan pembatalan dengan data yang ada. io_cancel_remove_all dan io_cancel_remove menghapus dan membatalkan permintaan dalam daftar. io_cancel_match_sequence memastikan urutan pembatalan sesuai. Fungsi-fungsi ini memungkinkan pembatalan operasi I/O secara efisien dalam io_uring.

### epoll.h
File ini mendeklarasikan empat fungsi terkait operasi epoll di io_uring, yang hanya tersedia jika kernel mendukung epoll. Fungsi-fungsinya mencakup persiapan dan pelaksanaan operasi untuk mengelola file descriptor dalam epoll (io_epoll_ctl), serta menunggu event yang terjadi pada file descriptor tersebut (io_epoll_wait). Semua fungsi ini bertujuan untuk meningkatkan efisiensi I/O non-blocking dalam io_uring.

### eventfd.h
Fungsi-fungsi dalam file ini mengelola eventfd dalam konteks io_uring. io_eventfd_register mendaftarkan eventfd ke dalam io_ring_ctx, sedangkan io_eventfd_unregister membatalkan pendaftarannya. io_eventfd_flush_signal memastikan sinyal eventfd hanya dipicu ketika ada perubahan status di completion queue, dan io_eventfd_signal memicu sinyal eventfd saat ada event yang memerlukan pemrosesan. Fungsi-fungsi ini mendukung operasi I/O asinkron dengan notifikasi berbasis eventfd.

### fdinfo.h
File ini mendeklarasikan fungsi io_uring_show_fdinfo yang digunakan untuk menampilkan informasi diagnostik terkait file descriptor dalam konteks io_uring. Fungsi ini mencetak status dan detail dari antrian Submission Queue (SQ) dan Completion Queue (CQ), termasuk informasi tentang thread yang terlibat, file yang digunakan, serta buffer yang terkait, untuk membantu memantau dan menganalisis operasi I/O dalam sistem.

### filetable.h
File ini berisi berbagai fungsi untuk mengelola tabel file pada io_uring di kernel Linux. Fungsi io_alloc_file_tables dan io_free_file_tables mengalokasikan dan membebaskan tabel file. io_fixed_fd_install dan __io_fixed_fd_install memasang file descriptor tetap, sedangkan io_fixed_fd_remove menghapusnya. Fungsi io_register_file_alloc_range mendaftarkan rentang alokasi file descriptor. Fungsi terkait bitmap seperti io_file_bitmap_clear dan io_file_bitmap_set mengatur status alokasi file descriptor. Fungsi io_file_get_flags mendapatkan flag file, sementara io_slot_flags, io_slot_file, dan io_fixed_file_set mengelola informasi file dalam konteks node sumber daya. Terakhir, io_file_table_set_alloc_range mengatur rentang alokasi file dalam konteks io_ring_ctx.

### fs.h
File ini berisi fungsi-fungsi yang mengelola operasi sistem berkas secara asinkron menggunakan io_uring di Linux. Fungsi-fungsi ini mencakup persiapan dan eksekusi operasi seperti mengganti nama berkas (io_renameat), menghapus berkas atau direktori (io_unlinkat), membuat direktori (io_mkdirat), membuat symbolic link (io_symlinkat), dan membuat hard link (io_linkat). Setiap operasi memiliki fungsi pembersihan memori setelahnya untuk memastikan pengelolaan sumber daya yang efisien.

### futex.h
Fungsi-fungsi dalam file ini mengelola operasi futex dalam konteks io_uring. Fungsi io_futex_prep dan io_futexv_prep menyiapkan permintaan untuk operasi futex tunggal atau ganda. io_futex_wait dan io_futexv_wait menangani penantian futex, sedangkan io_futex_wake digunakan untuk membangunkan futex. io_futex_cancel membatalkan operasi futex yang sedang berjalan, dan io_futex_remove_all menghapus semua futex terkait. Fungsi io_futex_cache_init dan io_futex_cache_free mengelola cache data futex untuk efisiensi.

### io_uring.h
File ini adalah header internal utama dalam subsistem io_uring di kernel Linux yang mendefinisikan berbagai konstanta, struktur, dan fungsi untuk mengelola operasi I/O asinkron. Di dalamnya terdapat fungsi-fungsi untuk menangani permintaan I/O (io_submit_sqes, io_req_task_complete), manajemen completion queue (io_get_cqe, io_commit_cqring), pengaturan file descriptor (io_file_get_normal, io_put_file), serta pengelolaan task work (io_req_task_work_add, io_run_task_work). File ini juga menyediakan mekanisme untuk deferred execution, busy poll, dan penguncian yang aman. Secara keseluruhan, file ini menjadi fondasi penting untuk memastikan koordinasi dan efisiensi tinggi dalam eksekusi io_uring.

### io-wq.h
File ini berisi deklarasi fungsi dan struktur untuk mengelola I/O workqueue (io_wq) dalam sistem io_uring Linux. Fungsi-fungsinya mencakup pembuatan (io_wq_create), penambahan pekerjaan (io_wq_enqueue), penandaan pekerjaan hashed (io_wq_hash_work), pembatalan pekerjaan (io_wq_cancel_cb), pengaturan afinitas CPU (io_wq_cpu_affinity), dan penghentian workqueue (io_wq_put_and_exit). Selain itu, ada fungsi untuk mendeteksi status worker, seperti saat aktif atau tidur. Semua ini memungkinkan eksekusi pekerjaan I/O blocking secara efisien di background.

### kbuf.h
Fungsi-fungsi dalam file ini berfokus pada pengelolaan buffer dalam konteks io_uring di kernel Linux. Fungsi utama mencakup pemilihan buffer (io_buffer_select), penyediaan dan penghapusan buffer (io_provide_buffers, io_remove_buffers), serta pendaftaran buffer ring (io_register_pbuf_ring). Fungsi-fungsi lain menangani daur ulang buffer, baik yang menggunakan metode legacy (io_kbuf_recycle_legacy) maupun buffer ring (io_kbuf_recycle_ring). Fungsi io_put_kbufs digunakan untuk menambahkan buffer ke dalam I/O, sedangkan io_kbuf_recycle menangani daur ulang buffer berdasarkan kondisi tertentu. Semua fungsi ini bekerja untuk memastikan manajemen buffer yang efisien dalam operasi I/O asinkron.

### memmap.h
Berfungsi sebagai manajemen memory mapping dalam io_uring, mendefinisikan fungsi dan struktur terkait pemetaan memori seperti io_pin_pages() (pin halaman user-space), io_uring_mmap() (setup mapping I/O), dan io_create_region() (alokasi region terpetakan). File ini juga menangani kasus non-MMU (CONFIG_MMU) dan menyediakan utilitas seperti io_region_get_ptr() untuk akses pointer aman ke region terpetakan.

### msg_ring.h
Header file untuk fitur message passing antar-ring dalam io_uring, menyediakan fungsi seperti io_msg_ring() (mengirim pesan antar-ring), io_msg_ring_prep() (persiapan request), dan io_uring_sync_msg_ring() (sinkronisasi pengiriman). File ini juga mencakup cleanup (io_msg_ring_cleanup) untuk membebaskan resource setelah operasi selesai.

### napi.h
Mengimplementasikan integrasi busy polling berbasis NAPI (New API) untuk io_uring, memungkinkan operasi I/O jaringan berlatensi rendah dengan fungsi seperti io_napi_busy_loop() (polling aktif), io_register_napi() (registrasi socket), dan io_napi_sqpoll_busy_poll() (optimasi SQPOLL). File ini hanya aktif jika CONFIG_NET_RX_BUSY_POLL di-enable, dengan fallback kosong untuk konfigurasi non-jaringan.

### net.h
Mengimplementasikan operasi jaringan asinkron untuk io_uring, menyediakan fungsi-fungsi seperti io_sendmsg(), io_recv(), io_accept(), dan io_connect() untuk menangani operasi socket secara efisien, termasuk dukungan zero-copy (io_send_zc), dengan struktur pendukung seperti io_async_msghdr untuk optimasi kinerja. File ini hanya aktif jika CONFIG_NET di-enable, menyediakan fallback kosong untuk sistem tanpa jaringan.

### nop.h
Mendefinisikan operasi no-operation (NOP) dalam io_uring, menyediakan fungsi io_nop_prep() untuk mempersiapkan dan io_nop() untuk mengeksekusi request kosong yang berguna untuk testing atau sinkronisasi ring tanpa efek samping.

### notif.h
Mengimplementasikan mekanisme notifikasi asinkron berbasis zero-copy dalam io_uring, dengan struktur io_notif_data untuk melacak buffer pengguna (ubuf_info) dan flag seperti IO_NOTIF_UBUF_FLAGS untuk optimasi transfer data. File ini menyediakan fungsi seperti io_alloc_notif() (alokasi notifikasi), io_notif_flush() (pembersihan resource), dan io_notif_account_mem() (manajemen memori), khususnya untuk skenario jaringan berkinerja tinggi dengan dukungan zero-copy reporting (zc_report/zc_used).

### opdef.h
Mendefinisikan karakteristik dan perilaku operasi I/O dalam io_uring melalui dua struktur utama: io_issue_def (menentukan properti ops seperti kebutuhan file, dukungan iopoll, dan fungsi issue/prep) dan io_cold_def (menangani cleanup dan fail cases), dengan array global io_issue_defs[] dan io_cold_defs[] sebagai lookup table untuk semua opcode yang didukung, serta fungsi utilitas seperti io_uring_op_supported() untuk validasi operasi.

### openclose.h
Mengimplementasikan operasi file asinkron terkait pembukaan dan penutupan dalam io_uring, menyediakan fungsi seperti io_openat()/io_openat2() (membuka file dengan opsi tambahan), io_close() (menutup file), dan io_install_fixed_fd() (mengaitkan fd ke fixed file table), termasuk preparasi request (*_prep) dan cleanup (io_open_cleanup), dengan dukungan fixed files melalui __io_close_fixed.

### poll.h
mengimplementasikan operasi polling asinkron dalam io_uring, menyediakan fungsi seperti io_poll_add() (registrasi event), io_poll_remove() (pembatalan polling), dan io_arm_poll_handler() (trigger notifikasi), dengan struktur io_poll untuk melacak file/event dan async_poll untuk penanganan double-poll, termasuk dukungan multishot (io_poll_multishot_retry) dan mekanisme cancel (io_poll_cancel).

### refs.h
Mengimplementasikan manajemen referensi atomik untuk request io_uring (io_kiocb), menyediakan fungsi seperti req_ref_get() (tambah referensi), req_ref_put() (kurangi referensi), dan req_ref_put_and_test() (pengecekan referensi nol), dengan proteksi overflow (req_ref_zero_or_close_to_overflow) dan warning untuk penggunaan tidak sah, memastikan lifecycle request dikelola secara thread-safe.

### register.h
Menangani operasi registrasi dan unregistrasi komponen io_uring seperti eventfd (io_eventfd_unregister) dan personalitas I/O (io_unregister_personality), serta menyediakan utilitas untuk mendapatkan file terdaftar (io_uring_register_get_file).

### rsrc.h
Mengelola sumber daya terdaftar (registered resources) dalam io_uring, termasuk file descriptors (IORING_RSRC_FILE) dan buffer (IORING_RSRC_BUFFER), dengan struktur seperti io_rsrc_node untuk tracking referensi dan io_mapped_ubuf untuk buffer mapping, menyediakan fungsi registrasi/unregistrasi (io_sqe_buffers_register, io_sqe_files_unregister), manajemen cache (io_rsrc_cache_init), serta utilitas impor/validasi buffer (io_import_reg_buf, io_buffer_validate) dengan dukungan thread-safe melalui reference counting dan optimasi memory (IO_VEC_CACHE_SOFT_CAP).

### rw.h

### slist.h

### splice.h

### sqpoll.h

### statx.h

### sync.h

### tctx.h

### timeout.h

### truncate.h

### uring_cmd.h

### waitid.h

### xattr.h

### zcrx.h