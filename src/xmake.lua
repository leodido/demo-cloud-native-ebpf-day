add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

-- using the vendored libbpf by default
option(
    "system-libbpf",
    {showmenu = true, default = false, description = "Use libbpf from the system"}
)

add_requires("libelf", "zlib")
add_requires("llvm >=10.x")
set_toolchains("@llvm")
-- add_requires("linux-headers")

add_includedirs("../vmlinux")

-- run `xmake f --system-libbpf=y` in case you want to use the system-installed libbpf
if has_config("system-libbpf") then
    add_requires("libbpf", {system = true})
else
    target("libbpf")
        set_kind("static")
        set_basename("bpf")
        add_files("../libbpf/src/*.c")
        add_includedirs("../libbpf/include")
        add_includedirs("../libbpf/include/uapi", {public = true})
        add_includedirs("$(buildir)", {interface = true})
        add_configfiles("../libbpf/src/(*.h)", {prefixdir = "bpf"})
        add_packages("libelf", "zlib")
end

-- Get Clang's default includes on this system.
-- Explicitly add these dirs to the includes list when compiling with `-target bpf`.
-- Otherwise some architecture-specific dirs will be "missing" on some architectures/distros:
-- headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h, sys/cdefs.h etc. -- might be missing.
--
-- Use '-isystem':
-- don't interfere with include mechanics except where the build would have failed anyways.
rule("platform.linux.bpf")
    before_buildcmd_file(function (target, batchcmds, sourcefile, opt)
        printf("detecting clang default includes for %s\n", sourcefile)
        local outfile = os.tmpfile()
        os.execv(
            "clang",
            {"-v", "-E", "-"},
            {stdin=os.nuldev(), stdout=outfile, stderr=outfile}
        )
        local outdata = io.readfile(outfile)
        local paths = string.match(outdata, "<...> search starts here:(.-)End of search list")
        for _, v in ipairs(paths:split("\n")) do
            target:add("sysincludedirs", v:trim())
        end
        os.rm(outfile)
    end)

target("restrict_connect")
    set_kind("binary")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end
    add_files("restrict_connect*.c")