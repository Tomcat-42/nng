const std = @import("std");
const log = std.log;
const SemanticVersion = std.SemanticVersion;
const zon = std.zon;
const fs = std.fs;
const Build = std.Build;
const Step = Build.Step;
const Module = Build.Module;
const Import = Module.Import;
const Target = std.Target;
const Os = Target.Os;
const assert = std.debug.assert;
const builtin = @import("builtin");

pub fn build(b: *Build) !void {
    // User options
    const BUILD_SHARED_LIBS = b.option(bool, "BUILD_SHARED_LIBS", "Build shared library. [Default = false]") orelse false;
    const NNG_ELIDE_DEPRECATED = b.option(bool, "NNG_ELIDE_DEPRECATED", "Elide deprecated functionality") orelse false;
    const NNG_SETSTACKSIZE = b.option(bool, "NNG_SETSTACKSIZE", "Use rlimit for thread stack size") orelse false;
    const NNG_ENABLE_STATS = b.option(bool, "NNG_ENABLE_STATS", "Enable statistics") orelse true;
    const NNG_SANITIZER = b.option([]const enum { address, leak, memory, thread, undefined }, "NNG_SANITIZER", "Enable sanitizer") orelse null;
    const NNG_COVERAGE = b.option(bool, "NNG_COVERAGE", "Enable coverage") orelse false;
    const NNG_HIDDEN_VISIBILITY = b.option(bool, "NNG_HIDDEN_VISIBILITY", "Enable hidden visibility") orelse false;

    const NNG_RESOLV_CONCURRENCY = b.option(usize, "NNG_RESOLV_CONCURRENCY", "Resolver (DNS) concurrency") orelse 4;
    const NNG_NUM_TASKQ_THREADS = b.option(usize, "NNG_NUM_TASKQ_THREADS", "Fixed number of task threads, 0 for automatic") orelse 0;
    const NNG_MAX_TASKQ_THREADS = b.option(usize, "NNG_MAX_TASKQ_THREADS", "Upper bound on task threads, 0 for no limit") orelse 16;
    const NNG_NUM_EXPIRE_THREADS = b.option(usize, "NNG_NUM_EXPIRE_THREADS", "Fixed number of expire threads, 0 for automatic") orelse 0;
    const NNG_MAX_EXPIRE_THREADS = b.option(usize, "NNG_MAX_EXPIRE_THREADS", "Upper bound on expire threads, 0 for no limit") orelse 8;
    const NNG_NUM_POLLER_THREADS = b.option(usize, "NNG_NUM_POLLER_THREADS", "Fixed number of I/O poller threads, 0 for automatic") orelse 0;
    const NNG_MAX_POLLER_THREADS = b.option(usize, "NNG_MAX_POLLER_THREADS", "Upper bound on I/O poller threads, 0 for no limit") orelse 8;
    const NNG_POLLQ_POLLER = b.option(enum { auto, ports, kqueue, epoll, poll, select }, "NNG_POLLQ_POLLER", "Poller to use for pollq") orelse .auto;

    const NNG_ENABLE_TLS = b.option(bool, "NNG_ENABLE_TLS", "Enable TLS support") orelse false;
    const NNG_TLS_ENGINE = b.option(enum { mbed, wolf }, "NNG_TLS_ENGINE", "TLS engine to use") orelse .mbed;
    const NNG_ENABLE_HTTP = b.option(bool, "NNG_ENABLE_HTTP", "Enable HTTP API") orelse true;
    const NNG_ENABLE_IPV6 = b.option(bool, "NNG_ENABLE_IPV6", "Enable IPv6") orelse false;

    const NNG_PROTO_BUS0 = b.option(bool, "NNG_PROTO_BUS0", "Enable BUSv0 protocol") orelse true;
    const NNG_PROTO_PAIR0 = b.option(bool, "NNG_PROTO_PAIR0", "Enable PAIRv0 protocol") orelse true;
    const NNG_PROTO_PAIR1 = b.option(bool, "NNG_PROTO_PAIR1", "Enable PAIRv1 protocol") orelse true;
    const NNG_PROTO_PUSH0 = b.option(bool, "NNG_PROTO_PUSH0", "Enable PUSHv0 protocol") orelse true;
    const NNG_PROTO_PULL0 = b.option(bool, "NNG_PROTO_PULL0", "Enable PULLv0 protocol") orelse true;
    const NNG_PROTO_PUB0 = b.option(bool, "NNG_PROTO_PUB0", "Enable PUBv0 protocol") orelse true;
    const NNG_PROTO_SUB0 = b.option(bool, "NNG_PROTO_SUB0", "Enable SUBv0 protocol") orelse true;
    const NNG_PROTO_REQ0 = b.option(bool, "NNG_PROTO_REQ0", "Enable REQv0 protocol") orelse true;
    const NNG_PROTO_REP0 = b.option(bool, "NNG_PROTO_REP0", "Enable REPv0 protocol") orelse true;
    const NNG_PROTO_RESPONDENT0 = b.option(bool, "NNG_PROTO_RESPONDENT0", "Enable RESPONDENTv0 protocol") orelse true;
    const NNG_PROTO_SURVEYOR0 = b.option(bool, "NNG_PROTO_SURVEYOR0", "Enable SURVEYORv0 protocol") orelse true;

    const NNG_TRANSPORT_INPROC = b.option(bool, "NNG_TRANSPORT_INPROC", "Enable inproc transport") orelse true;
    const NNG_TRANSPORT_IPC = b.option(bool, "NNG_TRANSPORT_IPC", "Enable IPC transport") orelse true;
    const NNG_TRANSPORT_TCP = b.option(bool, "NNG_TRANSPORT_TCP", "Enable TCP transport") orelse true;
    const NNG_TRANSPORT_TLS = b.option(bool, "NNG_TRANSPORT_TLS", "Enable TLS transport") orelse true;
    const NNG_TRANSPORT_WS = b.option(bool, "NNG_TRANSPORT_WS", "Enable WebSocket transport") orelse true;
    const NNG_TRANSPORT_WSS = (b.option(bool, "NNG_TRANSPORT_WSS", "Enable WSS Transport") orelse true) and NNG_ENABLE_TLS;
    const NNG_TRANSPORT_FDC = b.option(bool, "NNG_TRANSPORT_FDC", "Enable File Descriptor transport (EXPERIMENTAL)") orelse true;
    const NNG_TRANSPORT_UDP = b.option(bool, "NNG_TRANSPORT_UDP", "Enable UDP transport (EXPERIMENTAL)") orelse true;
    const NNG_SUPP_WEBSOCKET = NNG_TRANSPORT_WS or NNG_TRANSPORT_WSS;

    // Modules/Deps
    const upstream = b.dependency("nng", .{});
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var flags: std.ArrayListUnmanaged([]const u8) = .empty;
    try flags.appendSlice(b.allocator, &.{});

    const nng_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .omit_frame_pointer = false,
    });

    if (!BUILD_SHARED_LIBS) nng_mod.addCMacro("NNG_STATIC_LIB", "");
    if (NNG_ENABLE_STATS) nng_mod.addCMacro("NNG_ENABLE_STATS", "1");
    if (NNG_ELIDE_DEPRECATED) nng_mod.addCMacro("NNG_ELIDE_DEPRECATED", "");
    if (NNG_SETSTACKSIZE and target.result.os.tag != .windows) nng_mod.addCMacro("NNG_SETSTACKSIZE", "");
    if (NNG_SANITIZER) |sans|
        for (sans) |san|
            try flags.append(b.allocator, b.fmt("-fsanitize={s}", .{@tagName(san)}));
    if (NNG_ENABLE_TLS) {
        nng_mod.addCMacro("NNG_SUPP_TLS", "");
        nng_mod.addCMacro("NNG_TLS_ENGINE", @tagName(NNG_TLS_ENGINE));
    }
    if (NNG_ENABLE_HTTP) nng_mod.addCMacro("NNG_SUPP_HTTP", "");
    if (NNG_ENABLE_IPV6) nng_mod.addCMacro("NNG_ENABLE_IPV6", "");
    if (NNG_COVERAGE) {
        nng_mod.addCMacro("NNG_COVERAGE", "");
        // try testing_flags.appendSlice(b.allocator, &.{ "-g", "-O0", "--coverage" });
    }
    if (NNG_HIDDEN_VISIBILITY and target.result.os.tag != .windows) {
        nng_mod.addCMacro("NNG_HIDDEN_VISIBILITY", "");
        try flags.append(b.allocator, "-fvisibility=hidden");
    }
    nng_mod.addCMacro("NNG_RESOLV_CONCURRENCY", b.fmt("{d}", .{NNG_RESOLV_CONCURRENCY}));
    nng_mod.addCMacro("NNG_NUM_TASKQ_THREADS", b.fmt("{d}", .{NNG_NUM_TASKQ_THREADS}));
    nng_mod.addCMacro("NNG_MAX_TASKQ_THREADS", b.fmt("{d}", .{NNG_MAX_TASKQ_THREADS}));
    nng_mod.addCMacro("NNG_NUM_EXPIRE_THREADS", b.fmt("{d}", .{NNG_NUM_EXPIRE_THREADS}));
    nng_mod.addCMacro("NNG_MAX_EXPIRE_THREADS", b.fmt("{}", .{NNG_MAX_EXPIRE_THREADS}));
    nng_mod.addCMacro("NNG_NUM_POLLER_THREADS", b.fmt("{}", .{NNG_NUM_POLLER_THREADS}));
    nng_mod.addCMacro("NNG_MAX_POLLER_THREADS", b.fmt("{}", .{NNG_MAX_POLLER_THREADS}));

    switch (target.result.cpu.arch.endian()) {
        .big => nng_mod.addCMacro("NNG_BIG_ENDIAN", "1"),
        .little => nng_mod.addCMacro("NNG_LITTLE_ENDIAN", "1"),
    }

    switch (target.result.os.tag) {
        .linux => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_LINUX", "");
            nng_mod.addCMacro("NNG_USE_EVENTFD", "");
            nng_mod.addCMacro("NNG_HAVE_ABSTRACT_SOCKETS", "");
            if (target.result.abi.isAndroid()) nng_mod.addCMacro("NNG_PLATFORM_ANDROID", "");
        },
        .driverkit, .ios, .macos, .tvos, .visionos, .watchos => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_DARWIN", "");
        },
        .freebsd => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_FREEBSD", "");
        },
        .netbsd => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_NETBSD", "");
        },
        .openbsd => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_OPENBSD", "");
        },
        .solaris, .illumos => {
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
            nng_mod.addCMacro("NNG_PLATFORM_SUNOS", "");
        },
        .windows => {
            assert(target.result.os.isAtLeast(.windows, Os.WindowsVersion.vista).?);

            nng_mod.addCMacro("NNG_PLATFORM_WINDOWS", "");
            nng_mod.addCMacro("_CRT_SECURE_NO_WARNINGS", "");
            nng_mod.addCMacro("_CRT_RAND_S", "");
            nng_mod.addCMacro("_WIN32_WINNT", "0x0600");
        },
        else => |tag| {
            log.warn("WARNING: This platform may not be supported: {s}", .{@tagName(tag)});
            log.warn("Please consider opening an issue at https://github.com/nanomsg/nng", .{});
            nng_mod.addCMacro("NNG_PLATFORM_POSIX", "");
        },
    }

    nng_mod.addIncludePath(upstream.path("include"));
    nng_mod.addIncludePath(upstream.path("src"));

    nng_mod.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = &.{
            "src/nng.c",         "src/nng_legacy.c",   "include/nng/nng.h",   "include/nng/args.h",  "include/nng/http.h",
            "src/core/aio.c",    "src/core/device.c",  "src/core/dialer.c",   "src/core/sockfd.c",   "src/core/file.c",
            "src/core/idhash.c", "src/core/init.c",    "src/core/list.c",     "src/core/listener.c", "src/core/lmq.c",
            "src/core/log.c",    "src/core/message.c", "src/core/msgqueue.c", "src/core/options.c",  "src/core/pollable.c",
            "src/core/panic.c",  "src/core/pipe.c",    "src/core/reap.c",     "src/core/refcnt.c",   "src/core/sockaddr.c",
            "src/core/socket.c", "src/core/stats.c",   "src/core/stream.c",   "src/core/strs.c",     "src/core/taskq.c",
            "src/core/tcp.c",    "src/core/thread.c",  "src/core/url.c",
        },
        // .flags = flags.items,
    });

    switch (target.result.os.tag) {
        .windows => {
            nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/windows"),
                .files = &.{
                    "win_clock.c",   "win_debug.c",   "win_file.c",      "win_io.c",
                    "win_ipcconn.c", "win_ipcdial.c", "win_ipclisten.c", "win_pipe.c",
                    "win_rand.c",    "win_resolv.c",  "win_sockaddr.c",  "win_socketpair.c",
                    "win_tcp.c",     "win_tcpconn.c", "win_tcpdial.c",   "win_tcplisten.c",
                    "win_thread.c",  "win_udp.c",
                },
                .flags = flags.items,
            });
        },
        else => |tag| { // If not windows, assume posix (see NNG_PLATFORM_* above)
            // NOTE: Find a better way to link pthreads
            nng_mod.linkSystemLibrary("pthread", .{
                .needed = true,
                .preferred_link_mode = .static,
            });

            nng_mod.addCMacro("_GNU_SOURCE", "");
            nng_mod.addCMacro("_REENTRANT", "");
            nng_mod.addCMacro("_THREAD_SAFE", "");
            nng_mod.addCMacro("_POSIX_PTHREAD_SEMANTICS", "");

            // NOTE: Should check if those symbols exists before assuming true.
            // nng_mod.addCMacro("NNG_HAVE_LOCKF", ""); // lockf
            const NNG_HAVE_LOCKF = true;
            _ = NNG_HAVE_LOCKF; // autofix
            // nng_mod.addCMacro("NNG_HAVE_FLOCK", ""); // flock
            const NNG_HAVE_FLOCK = true;
            _ = NNG_HAVE_FLOCK; // autofix
            // nng_mod.addCMacro("NNG_HAVE_GETENTROPY", ""); // getentropy
            const NNG_HAVE_GETENTROPY = true;
            // nng_mod.addCMacro("NNG_HAVE_GETRANDOM", ""); // getrandom
            const NNG_HAVE_GETRANDOM = true;
            const NNG_HAVE_ARC4RANDOM = true;
            if (NNG_HAVE_ARC4RANDOM) nng_mod.addCMacro("NNG_HAVE_ARC4RANDOM", ""); // arc4random_buf
            // nng_mod.addCMacro("NNG_HAVE_RECVMSG", ""); // recvmsg
            const NNG_HAVE_RECVMSG = true;
            _ = NNG_HAVE_RECVMSG; // autofix
            // nng_mod.addCMacro("NNG_HAVE_SENDMSG", ""); // sendmsg
            const NNG_HAVE_SENDMSG = true;
            _ = NNG_HAVE_SENDMSG; // autofix
            // nng_mod.addCMacro("NNG_HAVE_CLOCK_GETTIME", ""); // clock_gettime (in libc or compiler-rt)
            const NNG_HAVE_CLOCK_GETTIME = true;
            _ = NNG_HAVE_CLOCK_GETTIME; // autofix
            // nng_mod.addCMacro("NNG_HAVE_SEMAPHORE_PTHREAD", ""); // sem_wait, pthread
            const NNG_HAVE_SEMAPHORE_PTHREAD = true;
            _ = NNG_HAVE_SEMAPHORE_PTHREAD; // autofix
            // nng_mod.addCMacro("NNG_HAVE_PTHREAD_ATFORK_PTHREAD", ""); // pthread_atfork, pthread
            const NNG_HAVE_PTHREAD_ATFORK_PTHREAD = true;
            _ = NNG_HAVE_PTHREAD_ATFORK_PTHREAD; // autofix
            // nng_mod.addCMacro("NNG_HAVE_PTHREAD_SET_NAME_NP", ""); // pthread_set_name_np, pthread
            const NNG_HAVE_PTHREAD_SET_NAME_NP = true;
            _ = NNG_HAVE_PTHREAD_SET_NAME_NP; // autofix
            // nng_mod.addCMacro("NNG_HAVE_PTHREAD_SETNAME_NP", ""); // pthread_setname_np, pthread
            const NNG_HAVE_PTHREAD_SETNAME_NP = true;
            _ = NNG_HAVE_PTHREAD_SETNAME_NP; // autofix
            // nng_mod.addCMacro("NNG_HAVE_LIBNSL", ""); // gethostbyname, nsl
            const NNG_HAVE_LIBNSL = true;
            _ = NNG_HAVE_LIBNSL; // autofix
            // nng_mod.addCMacro("NNG_HAVE_LIBSOCKET", ""); // socket, socket
            const NNG_HAVE_LIBSOCKET = true;
            _ = NNG_HAVE_LIBSOCKET; // autofix
            // nng_mod.addCMacro("NNG_HAVE_LIBATOMIC", ""); // __atomic_load_1, atomic
            const NNG_HAVE_LIBATOMIC = true;
            _ = NNG_HAVE_LIBATOMIC; // autofix
            // nng_mod.addCMacro("NNG_HAVE_UNIX_SOCKETS", ""); // AF_UNIX, sys/socket.h
            const NNG_HAVE_UNIX_SOCKETS = true;
            _ = NNG_HAVE_UNIX_SOCKETS; // autofix
            // nng_mod.addCMacro("NNG_HAVE_BACKTRACE", ""); // backtrace_symbols_fd, execinfo.h
            const NNG_HAVE_BACKTRACE = true;
            _ = NNG_HAVE_BACKTRACE; // autofix
            // nng_mod.addCMacro("NNG_HAVE_MSG_CONTROL", ""); // msghdr.msg_control, sys/socket.h
            const NNG_HAVE_MSG_CONTROL = true;
            _ = NNG_HAVE_MSG_CONTROL; // autofix
            // nng_mod.addCMacro("NNG_HAVE_EVENTFD", ""); // eventfd, sys/eventfd.h
            const NNG_HAVE_EVENTFD = true;
            _ = NNG_HAVE_EVENTFD; // autofix
            // nng_mod.addCMacro("NNG_HAVE_KQUEUE", ""); // kqueue, sys/event.h
            const NNG_HAVE_KQUEUE = true;
            // nng_mod.addCMacro("NNG_HAVE_PORT_CREATE", ""); // port_create, port.h
            const NNG_HAVE_PORT_CREATE = true;
            nng_mod.addCMacro("NNG_HAVE_EPOLL", ""); // epoll_create, sys/epoll.h
            const NNG_HAVE_EPOLL = true;
            const NNG_HAVE_EPOLL_CREATE1 = true;
            nng_mod.addCMacro("NNG_HAVE_EPOLL_CREATE1", if (NNG_HAVE_EPOLL_CREATE1) "1" else "0"); // epoll_create1, sys/epoll.h

            nng_mod.addCMacro("NNG_HAVE_POLL", ""); // poll, poll.h
            const NNG_HAVE_POLL = true;
            nng_mod.addCMacro("NNG_HAVE_SELECT", ""); // select, sys/select.h
            const NNG_HAVE_SELECT = true;

            const NNG_HAVE_GETPEEREID = tag.isBSD() or tag.isDarwin();
            if (NNG_HAVE_GETPEEREID) nng_mod.addCMacro("NNG_HAVE_GETPEEREID", ""); // getpeereid, unistd.h

            nng_mod.addCMacro("NNG_HAVE_SOPEERCRED", ""); // SO_PEERCRED, sys/socket.h
            const NNG_HAVE_SOPEERCRED = true;
            _ = NNG_HAVE_SOPEERCRED; // autofix

            const NNG_HAVE_SOCKPEERCRED = tag.isBSD() or tag.isDarwin();
            if (NNG_HAVE_SOCKPEERCRED) nng_mod.addCMacro("NNG_HAVE_SOCKPEERCRED", ""); // sockpeercred.uid, sys/socket.h

            const NNG_HAVE_LOCALPEERCRED = tag.isBSD() or tag.isDarwin();
            if (NNG_HAVE_LOCALPEERCRED) nng_mod.addCMacro("NNG_HAVE_LOCALPEERCRED", ""); // LOCAL_PEERCRED, sys/un.h

            nng_mod.addCMacro("NNG_HAVE_LOCALPEERPID", ""); // LOCAL_PEERPID, sys/un.h
            const NNG_HAVE_LOCALPEERPID = true;
            _ = NNG_HAVE_LOCALPEERPID; // autofix

            const NNG_HAVE_GETPEERUCRED = tag.isBSD() or tag.isDarwin();
            if (NNG_HAVE_GETPEERUCRED) nng_mod.addCMacro("NNG_HAVE_GETPEERUCRED", ""); // getpeerucred, ucred.h

            nng_mod.addCMacro("NNG_HAVE_STDATOMIC", ""); // atomic_flag_test_and_set, stdatomic.h
            const NNG_HAVE_STDATOMIC = true;
            _ = NNG_HAVE_STDATOMIC; // autofix
            nng_mod.addCMacro("NNG_HAVE_SOCKETPAIR", ""); // socketpair, sys/socket.h
            const NNG_HAVE_SOCKETPAIR = true;
            _ = NNG_HAVE_SOCKETPAIR; // autofix
            nng_mod.addCMacro("NNG_HAVE_INET6", ""); // AF_INET6, netinet/in.h
            const NNG_HAVE_INET6 = true;
            _ = NNG_HAVE_INET6; // autofix
            nng_mod.addCMacro("NNG_HAVE_INET6_BSD", ""); // AF_INET6, netinet6/in6.h
            const NNG_HAVE_INET6_BSD = true;
            _ = NNG_HAVE_INET6_BSD; // autofix
            nng_mod.addCMacro("NNG_HAVE_TIMESPEC_GET", ""); // timespec_get, time.h
            const NNG_HAVE_TIMESPEC_GET = true;
            _ = NNG_HAVE_TIMESPEC_GET; // autofix
            nng_mod.addCMacro("NNG_HAVE_SYS_RANDOM", ""); // getentropy, sys/random.h
            const NNG_HAVE_SYS_RANDOM = true;
            _ = NNG_HAVE_SYS_RANDOM; // autofix

            nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/posix"),
                .files = &.{
                    "posix_alloc.c",      "posix_atomic.c",  "posix_clock.c",      "posix_debug.c",
                    "posix_file.c",       "posix_ipcconn.c", "posix_ipcdial.c",    "posix_ipclisten.c",
                    "posix_peerid.c",     "posix_pipe.c",    "posix_resolv_gai.c", "posix_sockaddr.c",
                    "posix_socketpair.c", "posix_sockfd.c",  "posix_tcpconn.c",    "posix_tcpdial.c",
                    "posix_tcplisten.c",  "posix_thread.c",  "posix_udp.c",
                },
                .flags = flags.items,
            });

            poller: switch (NNG_POLLQ_POLLER) {
                .auto => if (NNG_HAVE_PORT_CREATE)
                    continue :poller .ports
                else if (NNG_HAVE_KQUEUE)
                    continue :poller .kqueue
                else if (NNG_HAVE_EPOLL)
                    continue :poller .epoll
                else if (NNG_HAVE_POLL)
                    continue :poller .poll
                else if (NNG_HAVE_SELECT)
                    continue :poller .select,
                .ports => {
                    std.debug.print("==================================PORTS====================================", .{});
                    nng_mod.addCMacro("NNG_POLLQ_PORTS", "");
                    nng_mod.addCSourceFiles(.{
                        .root = upstream.path("src/platform/posix"),
                        .files = &.{"posix_pollq_port.c"},
                        .flags = flags.items,
                    });
                },
                .kqueue => {
                    std.debug.print("==================================KQUEUE====================================", .{});
                    nng_mod.addCMacro("NNG_POLLQ_KQUEUE", "");
                    nng_mod.addCSourceFiles(.{
                        .root = upstream.path("src/platform/posix"),
                        .files = &.{"posix_pollq_kqueue.c"},
                        .flags = flags.items,
                    });
                },
                .epoll => {
                    std.debug.print("==================================EPOLL====================================", .{});
                    nng_mod.addCMacro("NNG_POLLQ_EPOLL", "");
                    nng_mod.addCSourceFiles(.{
                        .root = upstream.path("src/platform/posix"),
                        .files = &.{"posix_pollq_epoll.c"},
                        .flags = flags.items,
                    });
                },
                .poll => {
                    std.debug.print("==================================POLL====================================", .{});
                    nng_mod.addCMacro("NNG_POLLQ_POLL", "");
                    nng_mod.addCSourceFiles(.{
                        .root = upstream.path("src/platform/posix"),
                        .files = &.{"posix_pollq_poll.c"},
                        .flags = flags.items,
                    });
                },
                .select => {
                    std.debug.print("==================================SELECT====================================", .{});
                    nng_mod.addCMacro("NNG_POLLQ_SELECT", "");
                    nng_mod.addCSourceFiles(.{
                        .root = upstream.path("src/platform/posix"),
                        .files = &.{"posix_pollq_select.c"},
                        .flags = flags.items,
                    });
                },
            }

            if (NNG_HAVE_ARC4RANDOM) nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/posix"),
                .files = &.{"posix_rand_arc4random.c"},
                .flags = flags.items,
            }) else if (NNG_HAVE_GETENTROPY) nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/posix"),
                .files = &.{"posix_rand_getentropy.c"},
                .flags = flags.items,
            }) else if (NNG_HAVE_GETRANDOM) nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/posix"),
                .files = &.{"posix_rand_getrandom.c"},
                .flags = flags.items,
            }) else nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/platform/posix"),
                .files = &.{"posix_ran_urandom.c"},
                .flags = flags.items,
            });
        },
    }

    nng_mod.addCSourceFiles(.{
        .root = upstream.path("src/sp"),
        .files = &.{ "protocol.c", "transport.c" },

        .flags = flags.items,
    });
    if (NNG_PROTO_BUS0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/bus0"),
            .files = &.{"bus.c"},

            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_BUS0", "");
    }
    if (NNG_PROTO_PAIR0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pair0"),
            .files = &.{"pair.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_PAIR0", "");
    }
    if (NNG_PROTO_PAIR1) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pair1"),
            .files = &.{ "pair.c", "pair1_poly.c" },

            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_PAIR1", "");
    }
    if (NNG_PROTO_PUSH0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pipeline0"),
            .files = &.{"push.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_PUSH0", "");
    }
    if (NNG_PROTO_PULL0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pipeline0"),
            .files = &.{"pull.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_PULL0", "");
    }
    if (NNG_PROTO_PUB0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pubsub0"),
            .files = &.{"pub.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_PUB0", "");
    }
    if (NNG_PROTO_SUB0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/pubsub0"),
            .files = &.{ "sub.c", "xsub.c" },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_SUB0", "");
    }
    if (NNG_PROTO_REQ0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/reqrep0"),
            .files = &.{ "req.c", "xrep.c" },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_REQ0", "");
    }
    if (NNG_PROTO_REP0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/reqrep0"),
            .files = &.{ "rep.c", "xreq.c" },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_REP0", "");
    }
    if (NNG_PROTO_SURVEYOR0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/survey0"),
            .files = &.{ "survey.c", "xsurvey.c" },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_SURVEYOR0", "");
    }
    if (NNG_PROTO_RESPONDENT0) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/protocol/survey0"),
            .files = &.{ "respond.c", "xrespond.c" },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_HAVE_RESPONDENT0", "");
    }
    if (NNG_TRANSPORT_INPROC) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/inproc"),
            .files = &.{"inproc.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_INPROC", "");
    }
    if (NNG_TRANSPORT_IPC) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/ipc"),
            .files = &.{"ipc.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_IPC", "");
    }
    if (NNG_TRANSPORT_FDC) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/socket"),
            .files = &.{"sockfd.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_FDC", "");
    }
    if (NNG_TRANSPORT_TCP) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/tcp"),
            .files = &.{"tcp.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_TCP", "");
    }
    if (NNG_TRANSPORT_TLS) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/tls"),
            .files = &.{"tls.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_TLS", "");
    }
    if (NNG_TRANSPORT_UDP) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/udp"),
            .files = &.{"udp.c"},
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_TRANSPORT_UDP", "");
    }
    if (NNG_SUPP_WEBSOCKET) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/sp/transport/ws"),
            .files = &.{"websocket.c"},
            .flags = flags.items,
        });
        if (NNG_TRANSPORT_WS) nng_mod.addCMacro("NNG_TRANSPORT_WS", "");
        if (NNG_TRANSPORT_WSS) nng_mod.addCMacro("NNG_TRANSPORT_WSS", "");
    }

    nng_mod.addCSourceFiles(.{
        .root = upstream.path("src/supplemental/http"),
        .files = &.{"http_public.c"},
        .flags = flags.items,
    });

    if (NNG_ENABLE_HTTP) {
        nng_mod.addCSourceFiles(.{
            .root = upstream.path("src/supplemental/http"),
            .files = &.{
                "http_client.c", "http_chunk.c",   "http_conn.c",
                "http_msg.c",    "http_schemes.c", "http_server.c",
            },
            .flags = flags.items,
        });
        nng_mod.addCMacro("NNG_SUPP_HTTP", "");
    }

    nng_mod.addCSourceFiles(.{
        .root = upstream.path("src/supplemental/tls"),
        .files = &.{"tls_common.c"},
        .flags = flags.items,
    });

    if (NNG_ENABLE_TLS) switch (NNG_TLS_ENGINE) {
        .mbed => {
            nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/supplemental/tls/mbedtls"),
                .files = &.{"tls.c"},
                .flags = flags.items,
            });
            nng_mod.addCMacro("NNG_SUPP_TLS_MBEDTLS", "");
            // NOTE: Create mbedtls pkg
            nng_mod.linkSystemLibrary("mbedtls", .{ .needed = true });
        },
        .wolf => {
            nng_mod.addCSourceFiles(.{
                .root = upstream.path("src/supplemental/tls/wolfssl"),
                .files = &.{"tls_wolfssl.c"},
            });
            nng_mod.addCMacro("NNG_SUPP_TLS_WOLFSSL", "");
        },
    };

    if (NNG_SUPP_WEBSOCKET) nng_mod.addCSourceFiles(.{
        .root = upstream.path("src/supplemental/websocket"),
        .files = &.{
            "base64.c",
            "sha1.c",
            "websocket.c",
        },
        .flags = flags.items,
    });

    // Targets
    const nng = b.addLibrary(.{
        .name = "nng",
        .root_module = nng_mod,
        .linkage = if (BUILD_SHARED_LIBS) .dynamic else .static,
        .use_lld = true,
    });

    // Install
    b.installArtifact(nng);
    nng.installHeadersDirectory(
        upstream.path("include/"),
        "",
        .{},
    );
}
