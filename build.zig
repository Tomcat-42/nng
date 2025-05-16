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
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const upstream = b.dependency("nng", .{});
    const nng_mod = b.addModule("nng", .{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    var defs = try std.ArrayListUnmanaged(struct { []const u8, []const u8 }).initCapacity(b.allocator, 128);
    var sources = try std.ArrayListUnmanaged([]const u8).initCapacity(b.allocator, 128);
    var libs = try std.ArrayListUnmanaged([]const u8).initCapacity(b.allocator, 16);
    var flags = try std.ArrayListUnmanaged([]const u8).initCapacity(b.allocator, 16);

    {
        if (!BUILD_SHARED_LIBS) defs.appendAssumeCapacity(.{ "NNG_STATIC_LIB", "" });
        if (NNG_ENABLE_STATS) defs.appendAssumeCapacity(.{ "NNG_ENABLE_STATS", "1" });
        if (NNG_ELIDE_DEPRECATED) defs.appendAssumeCapacity(.{ "NNG_ELIDE_DEPRECATED", "" });
        if (NNG_SETSTACKSIZE and target.result.os.tag != .windows) defs.appendAssumeCapacity(.{ "NNG_SETSTACKSIZE", "" });
        if (NNG_SANITIZER) |sans| for (sans) |san|
            flags.appendAssumeCapacity(b.fmt("-fsanitize={s}", .{@tagName(san)}));
        if (NNG_ENABLE_TLS) {
            defs.appendSliceAssumeCapacity(&.{ .{ "NNG_SUPP_TLS", "" }, .{ "NNG_TLS_ENGINE", @tagName(NNG_TLS_ENGINE) } });
        }
        if (NNG_ENABLE_HTTP) defs.appendAssumeCapacity(.{ "NNG_SUPP_HTTP", "" });
        if (NNG_ENABLE_IPV6) defs.appendAssumeCapacity(.{ "NNG_ENABLE_IPV6", "" });
        if (NNG_COVERAGE) {
            defs.appendAssumeCapacity(.{ "NNG_COVERAGE", "" });
            // try testing_flags.appendSlice(b.allocator, &.{ "-g", "-O0", "--coverage" });
        }
        if (NNG_HIDDEN_VISIBILITY and target.result.os.tag != .windows) {
            defs.appendAssumeCapacity(.{ "NNG_HIDDEN_VISIBILITY", "" });
            flags.appendAssumeCapacity("-fvisibility=hidden");
        }
        defs.appendSliceAssumeCapacity(&.{
            .{ "NNG_RESOLV_CONCURRENCY", b.fmt("{d}", .{NNG_RESOLV_CONCURRENCY}) },
            .{ "NNG_NUM_TASKQ_THREADS", b.fmt("{d}", .{NNG_NUM_TASKQ_THREADS}) },
            .{ "NNG_MAX_TASKQ_THREADS", b.fmt("{d}", .{NNG_MAX_TASKQ_THREADS}) },
            .{ "NNG_NUM_EXPIRE_THREADS", b.fmt("{d}", .{NNG_NUM_EXPIRE_THREADS}) },
            .{ "NNG_MAX_EXPIRE_THREADS", b.fmt("{}", .{NNG_MAX_EXPIRE_THREADS}) },
            .{ "NNG_NUM_POLLER_THREADS", b.fmt("{}", .{NNG_NUM_POLLER_THREADS}) },
            .{ "NNG_MAX_POLLER_THREADS", b.fmt("{}", .{NNG_MAX_POLLER_THREADS}) },
        });

        switch (target.result.cpu.arch.endian()) {
            .big => defs.appendAssumeCapacity(.{ "NNG_BIG_ENDIAN", "1" }),
            .little => defs.appendAssumeCapacity(.{ "NNG_LITTLE_ENDIAN", "1" }),
        }

        switch (target.result.os.tag) {
            .linux => {
                defs.appendSliceAssumeCapacity(&.{
                    .{ "NNG_PLATFORM_POSIX", "" },
                    .{ "NNG_PLATFORM_LINUX", "" },
                    .{ "NNG_USE_EVENTFD", "" },
                    .{ "NNG_HAVE_ABSTRACT_SOCKETS", "" },
                });
                if (target.result.abi.isAndroid()) defs.appendAssumeCapacity(.{ "NNG_PLATFORM_ANDROID", "" });
            },
            .driverkit, .ios, .macos, .tvos, .visionos, .watchos => defs.appendSliceAssumeCapacity(&.{
                .{ "NNG_PLATFORM_POSIX", "" },
                .{ "NNG_PLATFORM_DARWIN", "" },
            }),
            .freebsd => defs.appendSliceAssumeCapacity(&.{
                .{ "NNG_PLATFORM_POSIX", "" },
                .{ "NNG_PLATFORM_FREEBSD", "" },
            }),
            .netbsd => defs.appendSliceAssumeCapacity(&.{
                .{ "NNG_PLATFORM_POSIX", "" },
                .{ "NNG_PLATFORM_NETBSD", "" },
            }),
            .openbsd => defs.appendSliceAssumeCapacity(&.{
                .{ "NNG_PLATFORM_POSIX", "" },
                .{ "NNG_PLATFORM_OPENBSD", "" },
            }),
            .solaris, .illumos => defs.appendSliceAssumeCapacity(&.{
                .{ "NNG_PLATFORM_POSIX", "" },
                .{ "NNG_PLATFORM_SUNOS", "" },
            }),
            .windows => {
                assert(target.result.os.isAtLeast(.windows, Os.WindowsVersion.vista).?);
                defs.appendSliceAssumeCapacity(&.{
                    .{ "NNG_PLATFORM_WINDOWS", "" },
                    .{ "_CRT_SECURE_NO_WARNINGS", "" },
                    .{ "_CRT_RAND_S", "" },
                    .{ "_WIN32_WINNT", "0x0600" },
                });
            },
            else => |tag| {
                log.warn("WARNING: This platform may not be supported: {s}", .{@tagName(tag)});
                log.warn("Please consider opening an issue at https://github.com/nanomsg/nng", .{});
                defs.appendAssumeCapacity(.{ "NNG_PLATFORM_POSIX", "" });
            },
        }

        sources.appendSliceAssumeCapacity(&.{
            "nng.c",           "nng_legacy.c",    "core/aio.c",      "core/device.c",
            "core/dialer.c",   "core/sockfd.c",   "core/file.c",     "core/idhash.c",
            "core/init.c",     "core/list.c",     "core/listener.c", "core/lmq.c",
            "core/log.c",      "core/message.c",  "core/msgqueue.c", "core/options.c",
            "core/pollable.c", "core/panic.c",    "core/pipe.c",     "core/reap.c",
            "core/refcnt.c",   "core/sockaddr.c", "core/socket.c",   "core/stats.c",
            "core/stream.c",   "core/strs.c",     "core/taskq.c",    "core/tcp.c",
            "core/thread.c",   "core/url.c",
        });

        switch (target.result.os.tag) {
            .windows => {
                sources.appendSliceAssumeCapacity(&.{
                    "platform/windows/win_clock.c",     "platform/windows/win_debug.c",    "platform/windows/win_file.c",
                    "platform/windows/win_io.c",        "platform/windows/win_ipcconn.c",  "platform/windows/win_ipcdial.c",
                    "platform/windows/win_ipclisten.c", "platform/windows/win_pipe.c",     "platform/windows/win_rand.c",
                    "platform/windows/win_resolv.c",    "platform/windows/win_sockaddr.c", "platform/windows/win_socketpair.c",
                    "platform/windows/win_tcp.c",       "platform/windows/win_tcpconn.c",  "platform/windows/win_tcpdial.c",
                    "platform/windows/win_tcplisten.c", "platform/windows/win_thread.c",   "platform/windows/win_udp.c",
                });
            },
            else => |tag| { // If not windows, assume posix (see NNG_PLATFORM_* above)
                libs.appendAssumeCapacity("pthread");
                defs.appendSliceAssumeCapacity(&.{
                    .{ "_GNU_SOURCE", "" },
                    .{ "_REENTRANT", "" },
                    .{ "_THREAD_SAFE", "" },
                    .{ "_POSIX_PTHREAD_SEMANTICS", "" },
                });

                // NOTE: Those are gross assumptions based on the OS
                // TODO: Check the API symbols in system headers
                const NNG_HAVE_LOCKF = true; // POSIX lockf
                const NNG_HAVE_FLOCK = tag.isBSD(); // BSD flock
                const NNG_HAVE_RECVMSG = true; // POSIX recvmsg
                const NNG_HAVE_SENDMSG = true; // POSIX sendmsg
                const NNG_HAVE_CLOCK_GETTIME = true; // POSIX clock_gettime (in libc or compiler-rt)
                const NNG_HAVE_SEMAPHORE_PTHREAD = true; // POSIX sem_wait, pthread
                const NNG_HAVE_PTHREAD_ATFORK_PTHREAD = true; // POSIX pthread_atfork, pthread
                const NNG_HAVE_PTHREAD_SET_NAME_NP = tag.isBSD() or tag.isDarwin(); // BSD pthread_set_name_np
                const NNG_HAVE_PTHREAD_SETNAME_NP = tag == .linux or tag.isDarwin(); // Linux pthread_setname_np
                const NNG_HAVE_LIBNSL = tag.isSolarish(); // Solaris gethostbyname, nsl
                const NNG_HAVE_LIBSOCKET = tag.isSolarish(); // Solaris socket, libsocket
                const NNG_HAVE_LIBATOMIC = true; // POSIX __atomic_load_1, atomic
                const NNG_HAVE_UNIX_SOCKETS = true; // POSIX AF_UNIX, sys/socket.h
                const NNG_HAVE_BACKTRACE = tag.isBSD() or tag == .linux; // BSD/Linux backtrace_symbols_fd, execinfo.h
                const NNG_HAVE_MSG_CONTROL = true; // POSIX msghdr.msg_control, sys/socket.h
                const NNG_HAVE_EVENTFD = tag == .linux; // Linux eventfd, sys/eventfd.h
                const NNG_HAVE_SOPEERCRED = tag == .linux; // Linux SO_PEERCRED, sys/socket.h
                const NNG_HAVE_LOCALPEERPID = tag.isBSD(); // BSD LOCAL_PEERPID, sys/un.h
                const NNG_HAVE_STDATOMIC = true; // POSIX atomic_flag_test_and_set, stdatomic.h
                const NNG_HAVE_SOCKETPAIR = true; // POSIX socketpair, sys/socket.h
                const NNG_HAVE_INET6 = true; // POSIX AF_INET6, netinet/in.h
                const NNG_HAVE_INET6_BSD = tag.isBSD(); // BSD-specific AF_INET6, netinet6/in6.h
                const NNG_HAVE_TIMESPEC_GET = true; // POSIX timespec_get, time.h
                const NNG_HAVE_SYS_RANDOM = tag.isBSD() or tag == .linux; // BSD/Linux getentropy, sys/random.h
                const NNG_HAVE_GETPEEREID = tag.isBSD(); // BSD/macOS getpeereid, unistd.h
                const NNG_HAVE_SOCKPEERCRED = tag.isBSD(); // BSD/macOS sockpeercred.uid, sys/socket.h
                const NNG_HAVE_LOCALPEERCRED = tag.isBSD(); // BSD/macOS LOCAL_PEERCRED, sys/un.h
                const NNG_HAVE_GETPEERUCRED = tag.isSolarish(); // Solaris getpeerucred, ucred.h

                if (NNG_HAVE_LOCKF) defs.appendAssumeCapacity(.{ "NNG_HAVE_LOCKF", "" });
                if (NNG_HAVE_FLOCK) defs.appendAssumeCapacity(.{ "NNG_HAVE_FLOCK", "" });
                if (NNG_HAVE_RECVMSG) defs.appendAssumeCapacity(.{ "NNG_HAVE_RECVMSG", "" });
                if (NNG_HAVE_SENDMSG) defs.appendAssumeCapacity(.{ "NNG_HAVE_SENDMSG", "" });
                if (NNG_HAVE_CLOCK_GETTIME) defs.appendAssumeCapacity(.{ "NNG_HAVE_CLOCK_GETTIME", "" });
                if (NNG_HAVE_SEMAPHORE_PTHREAD) defs.appendAssumeCapacity(.{ "NNG_HAVE_SEMAPHORE_PTHREAD", "" });
                if (NNG_HAVE_PTHREAD_ATFORK_PTHREAD) defs.appendAssumeCapacity(.{ "NNG_HAVE_PTHREAD_ATFORK_PTHREAD", "" });
                if (NNG_HAVE_PTHREAD_SET_NAME_NP) defs.appendAssumeCapacity(.{ "NNG_HAVE_PTHREAD_SET_NAME_NP", "" });
                if (NNG_HAVE_PTHREAD_SETNAME_NP) defs.appendAssumeCapacity(.{ "NNG_HAVE_PTHREAD_SETNAME_NP", "" });
                if (NNG_HAVE_LIBNSL) defs.appendAssumeCapacity(.{ "NNG_HAVE_LIBNSL", "" });
                if (NNG_HAVE_LIBSOCKET) defs.appendAssumeCapacity(.{ "NNG_HAVE_LIBSOCKET", "" });
                if (NNG_HAVE_LIBATOMIC) defs.appendAssumeCapacity(.{ "NNG_HAVE_LIBATOMIC", "" });
                if (NNG_HAVE_UNIX_SOCKETS) defs.appendAssumeCapacity(.{ "NNG_HAVE_UNIX_SOCKETS", "" });
                if (NNG_HAVE_BACKTRACE) defs.appendAssumeCapacity(.{ "NNG_HAVE_BACKTRACE", "" });
                if (NNG_HAVE_MSG_CONTROL) defs.appendAssumeCapacity(.{ "NNG_HAVE_MSG_CONTROL", "" });
                if (NNG_HAVE_EVENTFD) defs.appendAssumeCapacity(.{ "NNG_HAVE_EVENTFD", "" });
                if (NNG_HAVE_GETPEEREID) defs.appendAssumeCapacity(.{ "NNG_HAVE_GETPEEREID", "" });
                if (NNG_HAVE_SOPEERCRED) defs.appendAssumeCapacity(.{ "NNG_HAVE_SOPEERCRED", "" });
                if (NNG_HAVE_SOCKPEERCRED) defs.appendAssumeCapacity(.{ "NNG_HAVE_SOCKPEERCRED", "" });
                if (NNG_HAVE_LOCALPEERCRED) defs.appendAssumeCapacity(.{ "NNG_HAVE_LOCALPEERCRED", "" });
                if (NNG_HAVE_LOCALPEERPID) defs.appendAssumeCapacity(.{ "NNG_HAVE_LOCALPEERPID", "" });
                if (NNG_HAVE_GETPEERUCRED) defs.appendAssumeCapacity(.{ "NNG_HAVE_GETPEERUCRED", "" });
                if (NNG_HAVE_STDATOMIC) defs.appendAssumeCapacity(.{ "NNG_HAVE_STDATOMIC", "" });
                if (NNG_HAVE_SOCKETPAIR) defs.appendAssumeCapacity(.{ "NNG_HAVE_SOCKETPAIR", "" });
                if (NNG_HAVE_INET6) defs.appendAssumeCapacity(.{ "NNG_HAVE_INET6", "" });
                if (NNG_HAVE_INET6_BSD) defs.appendAssumeCapacity(.{ "NNG_HAVE_INET6_BSD", "" });
                if (NNG_HAVE_TIMESPEC_GET) defs.appendAssumeCapacity(.{ "NNG_HAVE_TIMESPEC_GET", "" });
                if (NNG_HAVE_SYS_RANDOM) defs.appendAssumeCapacity(.{ "NNG_HAVE_SYS_RANDOM", "" });

                sources.appendSliceAssumeCapacity(&.{
                    "platform/posix/posix_alloc.c",      "platform/posix/posix_atomic.c",     "platform/posix/posix_clock.c",
                    "platform/posix/posix_debug.c",      "platform/posix/posix_file.c",       "platform/posix/posix_ipcconn.c",
                    "platform/posix/posix_ipcdial.c",    "platform/posix/posix_ipclisten.c",  "platform/posix/posix_peerid.c",
                    "platform/posix/posix_pipe.c",       "platform/posix/posix_resolv_gai.c", "platform/posix/posix_sockaddr.c",
                    "platform/posix/posix_socketpair.c", "platform/posix/posix_sockfd.c",     "platform/posix/posix_tcpconn.c",
                    "platform/posix/posix_tcpdial.c",    "platform/posix/posix_tcplisten.c",  "platform/posix/posix_thread.c",
                    "platform/posix/posix_udp.c",
                });

                // NOTE: Those are just approximations based on the OS
                // TODO: Check the APIs symbols in system headers
                const NNG_HAVE_KQUEUE = tag.isBSD(); // kqueue, sys/event.h
                const NNG_HAVE_PORT_CREATE = tag.isSolarish(); // port_create, port.h
                const NNG_HAVE_EPOLL = tag == .linux; // epoll_create, sys/epoll.h
                const NNG_HAVE_EPOLL_CREATE1 = NNG_HAVE_EPOLL; // epoll_create1, sys/epoll.h
                // Posix fallbacks
                const NNG_HAVE_POLL = !NNG_HAVE_KQUEUE and !NNG_HAVE_PORT_CREATE and !NNG_HAVE_EPOLL; // poll, poll.h
                const NNG_HAVE_SELECT = true; // select, sys/select.h

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
                        continue :poller .select
                    else
                        unreachable,
                    .ports => {
                        defs.appendSliceAssumeCapacity(&.{ .{ "NNG_POLLQ_PORTS", "" }, .{ "NNG_HAVE_PORT_CREATE", "" } });
                        sources.appendAssumeCapacity("platform/posix/posix_pollq_port.c");
                    },
                    .kqueue => {
                        defs.appendSliceAssumeCapacity(&.{ .{ "NNG_POLLQ_KQUEUE", "" }, .{ "NNG_HAVE_KQUEUE", "" } });
                        sources.appendAssumeCapacity("platform/posix/posix_pollq_kqueue.c");
                    },
                    .epoll => {
                        defs.appendSliceAssumeCapacity(&.{ .{ "NNG_POLLQ_EPOLL", "" }, .{ "NNG_HAVE_EPOLL_CREATE1", if (NNG_HAVE_EPOLL_CREATE1) "1" else "0" }, .{ "NNG_HAVE_EPOLL", "" } });
                        sources.appendAssumeCapacity("platform/posix/posix_pollq_epoll.c");
                    },
                    .poll => {
                        defs.appendSliceAssumeCapacity(&.{ .{ "NNG_POLLQ_POLL", "" }, .{ "NNG_HAVE_POLL", "" } });
                        sources.appendAssumeCapacity("platform/posix/posix_pollq_poll.c");
                    },
                    .select => {
                        defs.appendSliceAssumeCapacity(&.{ .{ "NNG_POLLQ_SELECT", "" }, .{ "NNG_HAVE_SELECT", "" } });
                        sources.appendAssumeCapacity("platform/posix/posix_pollq_select.c");
                    },
                }

                // NOTE: Those *should be provided by libc* or compiler-rt
                // but the availability is not guaranteed (e.g. arc4random_buf
                // was added in glibc 2.36). But I will assume newer libcs
                // TODO: Same, check defs in headers
                const NNG_HAVE_ARC4RANDOM = !target.result.isMuslLibC(); // arc4random_buf
                const NNG_HAVE_GETENTROPY = true; // getentropy
                const NNG_HAVE_GETRANDOM = true; // getrandom

                if (NNG_HAVE_ARC4RANDOM) {
                    defs.appendAssumeCapacity(.{ "NNG_HAVE_ARC4RANDOM", "" });
                    sources.appendAssumeCapacity("platform/posix/posix_rand_arc4random.c");
                } else if (NNG_HAVE_GETENTROPY) {
                    defs.appendAssumeCapacity(.{ "NNG_HAVE_GETENTROPY", "" });
                    sources.appendAssumeCapacity("platform/posix/posix_rand_getentropy.c");
                } else if (NNG_HAVE_GETRANDOM) {
                    defs.appendAssumeCapacity(.{ "NNG_HAVE_GETRANDOM", "" });
                    sources.appendAssumeCapacity("platform/posix/posix_rand_getrandom.c");
                } else {
                    sources.appendAssumeCapacity("platform/posix/posix_ran_urandom.c");
                }
            },
        }

        sources.appendSliceAssumeCapacity(&.{ "sp/protocol.c", "sp/transport.c" });
        if (NNG_PROTO_BUS0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_BUS0", "" });
            sources.appendAssumeCapacity("sp/protocol/bus0/bus.c");
        }
        if (NNG_PROTO_PAIR0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_PAIR0", "" });
            sources.appendAssumeCapacity("sp/protocol/pair0/pair.c");
        }
        if (NNG_PROTO_PAIR1) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_PAIR1", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/pair1/pair.c", "sp/protocol/pair1/pair1_poly.c" });
        }
        if (NNG_PROTO_PUSH0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_PUSH0", "" });
            sources.appendAssumeCapacity("sp/protocol/pipeline0/push.c");
        }
        if (NNG_PROTO_PULL0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_PULL0", "" });
            sources.appendAssumeCapacity("sp/protocol/pipeline0/pull.c");
        }
        if (NNG_PROTO_PUB0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_PUB0", "" });
            sources.appendAssumeCapacity("sp/protocol/pubsub0/pub.c");
        }
        if (NNG_PROTO_SUB0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_SUB0", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/pubsub0/sub.c", "sp/protocol/pubsub0/xsub.c" });
        }
        if (NNG_PROTO_REQ0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_REQ0", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/reqrep0/xrep.c", "sp/protocol/reqrep0/req.c" });
        }
        if (NNG_PROTO_REP0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_REP0", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/reqrep0/rep.c", "sp/protocol/reqrep0/xreq.c" });
        }
        if (NNG_PROTO_SURVEYOR0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_SURVEYOR0", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/survey0/survey.c", "sp/protocol/survey0/xsurvey.c" });
        }
        if (NNG_PROTO_RESPONDENT0) {
            defs.appendAssumeCapacity(.{ "NNG_HAVE_RESPONDENT0", "" });
            sources.appendSliceAssumeCapacity(&.{ "sp/protocol/survey0/respond.c", "sp/protocol/survey0/xrespond.c" });
        }
        if (NNG_TRANSPORT_INPROC) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_INPROC", "" });
            sources.appendAssumeCapacity("sp/transport/inproc/inproc.c");
        }
        if (NNG_TRANSPORT_IPC) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_IPC", "" });
            sources.appendAssumeCapacity("sp/transport/ipc/ipc.c");
        }
        if (NNG_TRANSPORT_FDC) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_FDC", "" });
            sources.appendAssumeCapacity("sp/transport/socket/sockfd.c");
        }
        if (NNG_TRANSPORT_TCP) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_TCP", "" });
            sources.appendAssumeCapacity("sp/transport/tcp/tcp.c");
        }
        if (NNG_TRANSPORT_TLS) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_TLS", "" });
            sources.appendAssumeCapacity("sp/transport/tls/tls.c");
        }
        if (NNG_TRANSPORT_UDP) {
            defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_UDP", "" });
            sources.appendAssumeCapacity("sp/transport/udp/udp.c");
        }
        if (NNG_SUPP_WEBSOCKET) {
            sources.appendAssumeCapacity("sp/transport/ws/websocket.c");
            if (NNG_TRANSPORT_WS) defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_WS", "" });
            if (NNG_TRANSPORT_WSS) defs.appendAssumeCapacity(.{ "NNG_TRANSPORT_WSS", "" });
        }

        sources.appendAssumeCapacity("supplemental/http/http_public.c");

        if (NNG_ENABLE_HTTP) {
            defs.appendAssumeCapacity(.{ "NNG_SUPP_HTTP", "" });
            sources.appendSliceAssumeCapacity(&.{
                "supplemental/http/http_client.c",  "supplemental/http/http_chunk.c",
                "supplemental/http/http_conn.c",    "supplemental/http/http_msg.c",
                "supplemental/http/http_schemes.c", "supplemental/http/http_server.c",
            });
        }

        sources.appendAssumeCapacity("supplemental/tls/tls_common.c");
        if (NNG_ENABLE_TLS) switch (NNG_TLS_ENGINE) {
            .mbed => {
                // NOTE: Create mbedtls pkg
                defs.appendAssumeCapacity(.{ "NNG_SUPP_TLS_MBEDTLS", "" });
                sources.appendAssumeCapacity("supplemental/tls/mbedtls/tls.c");
                libs.appendAssumeCapacity("mbedtls");
            },
            .wolf => {
                // NOTE: Create wolfssl pkg
                defs.appendAssumeCapacity(.{ "NNG_SUPP_TLS_WOLFSSL", "" });
                sources.appendAssumeCapacity("supplemental/tls/wolfssl/tls_wolfssl.c");
                libs.appendAssumeCapacity("wolfssl");
            },
        };

        if (NNG_SUPP_WEBSOCKET) sources.appendSliceAssumeCapacity(&.{
            "supplemental/websocket/base64.c",
            "supplemental/websocket/sha1.c",
            "supplemental/websocket/websocket.c",
        });
    }

    nng_mod.addIncludePath(upstream.path("include"));
    nng_mod.addIncludePath(upstream.path("src"));

    for (libs.items) |lib| nng_mod.linkSystemLibrary(lib, .{ .needed = true, .preferred_link_mode = .static });
    for (defs.items) |def| nng_mod.addCMacro(def.@"0", def.@"1");
    nng_mod.addCSourceFiles(.{
        .root = upstream.path("src"),
        .files = sources.items,
        .flags = flags.items,
    });

    // Targets
    const nng = b.addLibrary(.{
        .name = "nng",
        .root_module = nng_mod,
        .linkage = if (BUILD_SHARED_LIBS) .dynamic else .static,
    });

    // Install
    b.installArtifact(nng);
    nng.installHeadersDirectory(
        upstream.path("include/"),
        "",
        .{},
    );

    // Clean
    const clean_step = b.step("clean", "Remove build artifacts");
    clean_step.dependOn(&b.addRemoveDirTree(b.path(fs.path.basename(b.install_path))).step);
    if (builtin.os.tag != .windows) clean_step.dependOn(&b.addRemoveDirTree(b.path(".zig-cache")).step);
}
