# nng

[nanomessage next generation](https://github.com/nanomsg/nng) packaged using the zig build system.

Currently it's only properly tested in linux. If you have a build bug in another platform feel free
to open a issue (or better, a PR).

## Usage

Add the dep to your `build.zig.zon`:

```bash
# master
zig fetch --save git+https://github.com/Tomcat-42/nng
# tagged release
zig fetch --save https://github.com/Tomcat-42/nng/archive/refs/tags/${tag}.tar.gz
```

Then in the `build.zig` file add the library as a dep:

```zig
const nng = b.dependency("nng", .{ .optimize = optimize, .target = target });
compile_target.linklibrary(nng.artifact("nng"));
```

Then, in your compile target:

```zig
const nng = @cImport({
    @cInclude("nng/nng.h");
    @cInclude("nng/args.h");
    @cInclude("nng/http.h");
});
```

Or alternatively, the `src/nng.zig` file exported as the `nng` module in the package
already do this for you:

```zig
const nng = b.dependency("nng", .{ .optimize = optimize, .target = target }).module("nng");
compile_target.addImport("nng", nng);
```

See the `examples/` folder for more usage cases.
