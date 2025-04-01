const std = @import("std");
const SemanticVersion = std.SemanticVersion;
const zon = std.zon;
const fs = std.fs;
const Build = std.Build;
const Step = Build.Step;
const Module = Build.Module;
const Import = Module.Import;
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{ .abi = .musl } });
    const optimize = b.standardOptimizeOption(.{});

    const http_client_mod = b.createModule(.{
        .root_source_file = b.path("src/http_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    const nng = b.dependency("nng", .{ .optimize = optimize, .target = target }).module("nng");
    http_client_mod.addImport("nng", nng);

    const http_client = b.addExecutable(.{
        .name = "http_client",
        .root_module = http_client_mod,
        .linkage = .static,
    });

    b.installArtifact(http_client);

    const run_cmd = b.addRunArtifact(http_client);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const clean_step = b.step("clean", "Remove build artifacts");
    clean_step.dependOn(&b.addRemoveDirTree(b.path(fs.path.basename(b.install_path))).step);
    if (builtin.os.tag != .windows)
        clean_step.dependOn(&b.addRemoveDirTree(b.path(".zig-cache")).step);
}
