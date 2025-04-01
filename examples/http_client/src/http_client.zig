const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const process = std.process;
const io = std.io;
const os = std.os;

const nng = @import("nng");

const stdout = io.getStdOut().writer();
const stderr = io.getStdErr().writer();
const allocator = std.heap.c_allocator;

pub fn main() !void {
    var client: *nng.nng_http_client = undefined;
    var conn: *nng.nng_http = undefined;
    var url: *nng.nng_url = undefined;
    var aio: *nng.nng_aio = undefined;
    var hdr: [*c]const u8 = undefined;
    var len: usize = 0;
    var data: []u8 = undefined;
    var iov: nng.nng_iov = undefined;

    if (os.argv.len < 2) {
        try stderr.print("Usage: {s} <url>\n", .{os.argv[0]});
        return error.InvalidArgument;
    }

    const my_url = os.argv[1];

    guard(nng.nng_init(null)) catch process.exit(1);
    defer nng.nng_fini();

    guard(nng.nng_aio_alloc(@ptrCast(&aio), null, null)) catch process.exit(1);
    defer nng.nng_aio_free(aio);

    guard(nng.nng_url_parse(@ptrCast(&url), my_url)) catch process.exit(1);
    defer nng.nng_url_free(url);

    guard(nng.nng_http_client_alloc(@ptrCast(&client), url)) catch process.exit(1);
    defer nng.nng_http_client_free(client);

    nng.nng_http_client_connect(client, aio);
    nng.nng_aio_wait(aio);
    guard(nng.nng_aio_result(aio)) catch process.exit(1);

    conn = @ptrCast(nng.nng_aio_get_output(aio, 0));
    nng.nng_http_write_request(conn, aio);
    nng.nng_aio_wait(aio);
    guard(nng.nng_aio_result(aio)) catch process.exit(1);

    nng.nng_http_read_response(conn, aio);
    nng.nng_aio_wait(aio);
    guard(nng.nng_aio_result(aio)) catch process.exit(1);

    if (nng.nng_http_get_status(conn) != nng.NNG_HTTP_STATUS_OK)
        try stderr.print("HTTP Server Responded: {d} {s}", .{
            nng.nng_http_get_status(conn),
            nng.nng_http_get_reason(conn),
        });

    hdr = nng.nng_http_get_header(conn, "Content-Length");
    if (hdr == null) {
        try stderr.print("No Content-Length header\n", .{});
        process.exit(1);
    }

    len = try fmt.parseInt(usize, mem.span(hdr), 10);
    data = try allocator.alloc(u8, len);

    iov.iov_len = len;
    iov.iov_buf = @ptrCast(data);

    guard(nng.nng_aio_set_iov(aio, 1, &iov)) catch process.exit(1);

    nng.nng_http_read_all(conn, aio);
    nng.nng_aio_wait(aio);
    guard(nng.nng_aio_result(aio)) catch process.exit(1);

    try stdout.print("Response: {s}\n", .{data});
}

inline fn guard(rv: anytype) !void {
    if (rv == 0) return;

    const msg = nng.nng_strerror(@as(c_uint, @intCast(rv)));
    stderr.print("{s}\n", .{msg}) catch {};
    return @errorFromInt(@as(std.meta.Int(.unsigned, @bitSizeOf(anyerror)), @intCast(rv)));
}
