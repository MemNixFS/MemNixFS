cmake_minimum_required(VERSION 3.20)
project(MemNixFS
    VERSION 0.37.1
    DESCRIPTION "Mount Linux memory dumps as a virtual filesystem"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W3 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Mount backends are host-specific: WinFsp on Windows, FUSE on Linux.
# CLI-only builds remain useful for smoke tests and automation.
if(WIN32)
    set(LMPFS_DEFAULT_WINFSP ON)
    set(LMPFS_DEFAULT_FUSE OFF)
else()
    set(LMPFS_DEFAULT_WINFSP OFF)
    set(LMPFS_DEFAULT_FUSE ON)
endif()

option(LMPFS_BUILD_MOUNT_WINFSP "Build the WinFsp mount backend" ${LMPFS_DEFAULT_WINFSP})
option(LMPFS_BUILD_MOUNT_FUSE   "Build the FUSE mount backend"   ${LMPFS_DEFAULT_FUSE})
option(LMPFS_BUILD_TESTS        "Build unit tests"                OFF)
set(LMPFS_CTEST_DUMP "" CACHE FILEPATH
    "Optional dump path used to register dump-backed CTest smoke tests")
# YARA scanning over user-process VMAs. ON by default so /search/yara.txt
# is part of the standard surface. Turn off only if libyara is missing
# from the toolchain (the build will then skip yara_search.{h,cpp}).
option(LMPFS_BUILD_YARA         "Build with YARA rule-scanning"   ON)

find_package(PkgConfig QUIET)

find_package(Snappy CONFIG QUIET)
if(TARGET Snappy::snappy)
    set(LMPFS_SNAPPY_TARGET Snappy::snappy)
else()
    if(PkgConfig_FOUND)
        pkg_check_modules(SNAPPY QUIET IMPORTED_TARGET snappy)
    endif()
    if(TARGET PkgConfig::SNAPPY)
        set(LMPFS_SNAPPY_TARGET PkgConfig::SNAPPY)
    else()
        message(FATAL_ERROR
            "Snappy development package not found. Install snappy/libsnappy-dev "
            "or use vcpkg.")
    endif()
endif()

find_package(LibLZMA REQUIRED)

find_package(nlohmann_json CONFIG QUIET)
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NOT NLOHMANN_JSON_INCLUDE_DIR)
        message(FATAL_ERROR
            "nlohmann-json development package not found. Install "
            "nlohmann-json3-dev/nlohmann-json-devel or use vcpkg.")
    endif()
    add_library(nlohmann_json_header_only INTERFACE)
    target_include_directories(nlohmann_json_header_only
        INTERFACE "${NLOHMANN_JSON_INCLUDE_DIR}")
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json_header_only)
endif()

find_package(fmt CONFIG QUIET)
if(TARGET fmt::fmt)
    set(LMPFS_FMT_TARGET fmt::fmt)
else()
    if(PkgConfig_FOUND)
        pkg_check_modules(FMT QUIET IMPORTED_TARGET fmt)
    endif()
    if(TARGET PkgConfig::FMT)
        set(LMPFS_FMT_TARGET PkgConfig::FMT)
    else()
        message(FATAL_ERROR
            "fmt development package not found. Install libfmt-dev/fmt-devel "
            "or use vcpkg.")
    endif()
endif()
if(LMPFS_BUILD_YARA)
    # vcpkg installs yara via `yara` CONFIG; on Windows it links against
    # OpenSSL transitively. If the package isn't present, fall back to
    # the no-yara build instead of failing the configure step.
    find_package(unofficial-libyara CONFIG QUIET)
    if(NOT unofficial-libyara_FOUND)
        find_package(yara CONFIG QUIET)
    endif()
    if(NOT unofficial-libyara_FOUND AND NOT yara_FOUND AND PkgConfig_FOUND)
        pkg_check_modules(YARA QUIET IMPORTED_TARGET yara)
    endif()
    if(NOT unofficial-libyara_FOUND AND NOT yara_FOUND AND NOT TARGET PkgConfig::YARA)
        message(WARNING
            "LMPFS_BUILD_YARA=ON but libyara CMake package not found. "
            "Skipping yara scanning support; /search/yara.txt will be absent. "
            "Install libyara-dev/yara-devel or run `vcpkg install yara:x64-windows` "
            "to enable it.")
        set(LMPFS_BUILD_YARA OFF)
    endif()
endif()

if(LMPFS_BUILD_MOUNT_FUSE)
    if(NOT PkgConfig_FOUND)
        message(FATAL_ERROR
            "FUSE mount requires pkg-config plus libfuse3-dev on Linux.")
    endif()
    pkg_check_modules(FUSE REQUIRED IMPORTED_TARGET fuse3)
    set(LMPFS_FUSE_USE_VERSION 31)
endif()

# --- core engine library ---------------------------------------------------
add_library(memnixfs_core STATIC
    src/core/types.h
    src/core/error.h
    src/core/log.h
    src/core/log.cpp
    src/core/stream.h

    src/io/memory_source.h
    src/io/file_memory_source.cpp
    src/io/mmap_memory_source.cpp

    src/formats/physical_layer.h
    src/formats/format_factory.h
    src/formats/format_factory.cpp
    src/formats/raw_format.cpp
    src/formats/lime_format.cpp
    src/formats/avml_format.cpp
    src/formats/kdump_format.cpp
    src/formats/phys_raw_stream.h

    src/symbols/isf_symbols.h
    src/symbols/isf_symbols.cpp
    src/symbols/xz_decompress.h
    src/symbols/xz_decompress.cpp
    src/symbols/symbol_resolver.h
    src/symbols/symbol_resolver.cpp
    src/symbols/symbol_cache_http.h
    src/symbols/symbol_cache_http.cpp
    src/symbols/btf_to_isf.h
    src/symbols/btf_to_isf.cpp
    src/symbols/kallsyms.h
    src/symbols/kallsyms.cpp

    src/arch/x86_64/paging.h
    src/arch/x86_64/paging.cpp
    src/arch/x86_64/page_cache.h
    src/arch/x86_64/page_cache.cpp

    src/os/linux/kernel_resolver.h
    src/os/linux/kernel_resolver.cpp
    src/os/linux/dtb_resolver.h
    src/os/linux/dtb_resolver.cpp
    src/os/linux/banner_scan.h
    src/os/linux/banner_scan.cpp
    src/os/linux/btf_probe.h
    src/os/linux/btf_probe.cpp
    src/os/linux/process.h
    src/os/linux/process_list.cpp
    src/os/linux/vma.h
    src/os/linux/vma.cpp
    src/os/linux/elf_core.h
    src/os/linux/elf_core.cpp
    src/os/linux/elf_core_stream.h
    src/os/linux/elf_core_stream.cpp
    src/os/linux/task_files.h
    src/os/linux/task_files.cpp
    src/os/linux/kva_reader.h
    src/os/linux/kva_reader.cpp
    src/os/linux/kern_va_stream.h
    src/os/linux/kern_va_stream.cpp
    src/os/linux/v2p_misc.h
    src/os/linux/v2p_misc.cpp
    src/os/linux/av_edr.h
    src/os/linux/av_edr.cpp
    src/os/linux/json_export.h
    src/os/linux/json_export.cpp
    src/os/linux/forensic_snapshot.h
    src/os/linux/forensic_snapshot.cpp
    src/os/linux/strings_search.h
    src/os/linux/strings_search.cpp
    src/os/linux/task_extras.h
    src/os/linux/task_extras.cpp
    src/os/linux/yara_search.h
    src/os/linux/yara_search.cpp
    src/os/linux/dentry_path.h
    src/os/linux/dentry_path.cpp
    src/os/linux/mountinfo.h
    src/os/linux/mountinfo.cpp
    src/os/linux/pagecache.h
    src/os/linux/pagecache.cpp
    src/os/linux/netstat.h
    src/os/linux/netstat.cpp
    src/os/linux/findevil.h
    src/os/linux/findevil.cpp
    src/os/linux/check_syscall.h
    src/os/linux/check_syscall.cpp
    src/os/linux/integrity_checks.h
    src/os/linux/integrity_checks.cpp
    src/os/linux/pscallstack.h
    src/os/linux/pscallstack.cpp
    src/os/linux/threads.h
    src/os/linux/threads.cpp
    src/os/linux/ebpf.h
    src/os/linux/ebpf.cpp
    src/os/linux/entropy.h
    src/os/linux/entropy.cpp
    src/os/linux/csv_export.h
    src/os/linux/csv_export.cpp
    src/os/linux/tracing.h
    src/os/linux/tracing.cpp
    src/os/linux/tracepoints.h
    src/os/linux/tracepoints.cpp
    src/os/linux/sysinfo.h
    src/os/linux/sysinfo.cpp
    src/os/linux/sysinfo_more.cpp
    src/os/linux/users.h
    src/os/linux/users.cpp
    src/os/linux/timeline.h
    src/os/linux/timeline.cpp
    src/os/linux/process_views.h
    src/os/linux/process_views.cpp
    src/os/linux/dmesg.h
    src/os/linux/dmesg.cpp
    src/os/linux/crash_journal.h
    src/os/linux/crash_journal.cpp
    src/os/linux/modules.h
    src/os/linux/modules.cpp
    src/os/linux/fdtable.h
    src/os/linux/fdtable.cpp
    src/os/linux/bash_history.h
    src/os/linux/bash_history.cpp

    src/vfs/vfs.h
    src/vfs/vfs.cpp
    src/vfs/proc_module.cpp
    src/vfs/sys_module.h
    src/vfs/sys_module.cpp
    src/vfs/forensic_warmer.h
    src/vfs/forensic_warmer.cpp

    src/app/engine.h
    src/app/engine.cpp
)
set_target_properties(memnixfs_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(memnixfs_core PUBLIC src)
target_compile_definitions(memnixfs_core PUBLIC LMPFS_VERSION="${PROJECT_VERSION}")
target_link_libraries(memnixfs_core
    PUBLIC  nlohmann_json::nlohmann_json ${LMPFS_FMT_TARGET}
    PRIVATE ${LMPFS_SNAPPY_TARGET} LibLZMA::LibLZMA)

# Conditional YARA support. Different vcpkg builds export the target as
# `unofficial::libyara::libyara` or `yara::libyara` — try the standard
# names and fall back to a plain link if neither exists.
if(LMPFS_BUILD_YARA)
    target_compile_definitions(memnixfs_core PUBLIC LMPFS_HAS_YARA=1)
    if(TARGET unofficial::libyara::libyara)
        target_link_libraries(memnixfs_core PRIVATE unofficial::libyara::libyara)
    elseif(TARGET yara::libyara)
        target_link_libraries(memnixfs_core PRIVATE yara::libyara)
    elseif(TARGET YARA::YARA)
        target_link_libraries(memnixfs_core PRIVATE YARA::YARA)
    elseif(TARGET PkgConfig::YARA)
        target_link_libraries(memnixfs_core PRIVATE PkgConfig::YARA)
    else()
        # vcpkg's yara port currently exposes a bare `libyara` target on
        # Windows-x64 — link by name as a last resort.
        target_link_libraries(memnixfs_core PRIVATE libyara)
    endif()
endif()

# --- CLI executable --------------------------------------------------------
# Note: the CLI links BOTH the static core (for Engine::create) AND the
# DLL (for the plugin scanner entry point). The DLL is the place where
# `lmpfs_plugin_add_file` is defined; co-locating the EXE with the DLL
# ensures plugins loaded via the EXE's `mount` subcommand resolve their
# add_file calls against the same symbol the scanner used.
add_executable(memnixfs
    src/cli/main.cpp)
target_link_libraries(memnixfs PRIVATE memnixfs_core memnixfs_dll)
if(UNIX)
    set_target_properties(memnixfs PROPERTIES
        INSTALL_RPATH "$ORIGIN/../lib")
endif()
# Embed a manifest selecting the UTF-8 active code page so non-ASCII paths
# (e.g. Chinese dump/symbol paths) round-trip correctly through argv,
# std::filesystem::path, CreateFileW and fmt output. Merged with the linker's
# auto-generated manifest via /MANIFESTINPUT. No effect on pre-1903 Windows.
if(MSVC)
    target_link_options(memnixfs PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/src/cli/memnixfs.manifest")
endif()

# --- C API DLL (Tier 6 foundation) -----------------------------------------
#
# Exposes the engine through a stable C ABI so any language with C FFI
# (Python ctypes, Rust bindgen, .NET P/Invoke, Java JNA, native C/C++) can
# drive it directly. See src/api/lmpfs.h for the surface.
#
# Forwards-compatible: this is the layer the future MemProcFS `VMMDLL_*`
# compatibility shim and the Volatility-3 compat shim build on.
add_library(memnixfs_dll SHARED
    src/api/lmpfs.h
    src/api/lmpfs.cpp
    src/api/lmpfs_plugin.h
    src/api/vmmdll_compat.h
    src/api/vmmdll_compat.cpp)
target_include_directories(memnixfs_dll PUBLIC src)
target_link_libraries(memnixfs_dll PRIVATE memnixfs_core)
# Give the produced DLL a stable, lower-case base name.
set_target_properties(memnixfs_dll PROPERTIES
    OUTPUT_NAME memnixfs
    PREFIX     "")

# --- C-API smoke test (only if tests enabled) ------------------------------
if(LMPFS_BUILD_TESTS)
    enable_testing()

    # Smoke driver is .cpp not .c — the C API itself is pure C (see
    # src/api/lmpfs.h's extern "C" block), but linking a .c executable
    # against a C++-emitted .lib requires either an .obj wrapper or
    # forcing LINKER_LANGUAGE, both of which trip CMake's source-type
    # heuristics. Renaming the driver to .cpp avoids the dance — the
    # body is valid C99 inside extern "C".
    add_executable(c_api_smoke tests/c_api/c_api_smoke.cpp)
    target_include_directories(c_api_smoke PRIVATE src)
    target_link_libraries(c_api_smoke PRIVATE memnixfs_dll)

    add_executable(vmmdll_smoke tests/c_api/vmmdll_smoke.cpp)
    target_include_directories(vmmdll_smoke PRIVATE src)
    target_link_libraries(vmmdll_smoke PRIVATE memnixfs_dll)
    if(LMPFS_CTEST_DUMP)
        add_test(NAME c_api_smoke COMMAND c_api_smoke "${LMPFS_CTEST_DUMP}")
        add_test(NAME vmmdll_smoke COMMAND vmmdll_smoke "${LMPFS_CTEST_DUMP}")
    endif()

    # Unit test for the multi-shell on-disk history parser. Links the static
    # core directly (the parser is a C++ symbol, not part of the C ABI) and
    # needs no memory dump — it feeds synthetic history-file content.
    add_executable(shell_history_test tests/unit/shell_history_test.cpp)
    target_include_directories(shell_history_test PRIVATE src)
    target_link_libraries(shell_history_test PRIVATE memnixfs_core)
    add_test(NAME shell_history_test COMMAND shell_history_test)

    add_executable(recovered_file_stats_test tests/unit/recovered_file_stats_test.cpp)
    target_include_directories(recovered_file_stats_test PRIVATE src)
    target_link_libraries(recovered_file_stats_test PRIVATE memnixfs_core)
    add_test(NAME recovered_file_stats_test COMMAND recovered_file_stats_test)

    add_executable(banner_scan_test tests/unit/banner_scan_test.cpp)
    target_include_directories(banner_scan_test PRIVATE src)
    target_link_libraries(banner_scan_test PRIVATE memnixfs_core)
    add_test(NAME banner_scan_test COMMAND banner_scan_test)

    add_executable(findevil_indicators_test tests/unit/findevil_indicators_test.cpp)
    target_include_directories(findevil_indicators_test PRIVATE src)
    target_link_libraries(findevil_indicators_test PRIVATE memnixfs_core)
    add_test(NAME findevil_indicators_test COMMAND findevil_indicators_test)

    # Sample plugin DLL — drops into LMPFS_PLUGINS_DIR or
    # %LOCALAPPDATA%\MemNixFS\plugins to demonstrate the plugin SDK.
    add_library(sample_plugin SHARED tests/c_api/sample_plugin.cpp)
    target_include_directories(sample_plugin PRIVATE src)
    target_link_libraries(sample_plugin PRIVATE memnixfs_dll)
    set_target_properties(sample_plugin PROPERTIES PREFIX "")
endif()

# --- WinFsp mount backend --------------------------------------------------
if(LMPFS_BUILD_MOUNT_WINFSP)
    if(NOT WIN32)
        message(FATAL_ERROR "WinFsp mount only supported on Windows")
    endif()
    set(WINFSP_INC "C:/Program Files (x86)/WinFsp/inc")
    set(WINFSP_LIB "C:/Program Files (x86)/WinFsp/lib/winfsp-x64.lib")
    if(NOT EXISTS "${WINFSP_INC}/winfsp/winfsp.h")
        message(FATAL_ERROR
            "WinFsp SDK not found at ${WINFSP_INC}.\n"
            "  This project requires WinFsp - it is the primary UX.\n"
            "  Install from https://winfsp.dev/ (free, ~5 MB).\n"
            "  If you really want a CLI-only build, configure with\n"
            "      -DLMPFS_BUILD_MOUNT_WINFSP=OFF\n"
            "  but the `mount` command will be missing.")
    endif()
    target_sources(memnixfs_core PRIVATE src/mount/winfsp_mount.cpp)
    target_compile_definitions(memnixfs_core PUBLIC LMPFS_HAS_WINFSP=1)
    target_include_directories(memnixfs_core PUBLIC ${WINFSP_INC})
    # Delay-load winfsp-x64.dll: the EXE can launch without it on PATH, and
    # preload_winfsp_dll() in run_winfsp_mount() LoadLibrary()s it from the
    # canonical install dir before the first WinFsp call.
    target_link_libraries(memnixfs_core PUBLIC ${WINFSP_LIB} delayimp.lib)
    target_link_options(memnixfs_core PUBLIC /DELAYLOAD:winfsp-x64.dll)
endif()

# --- FUSE mount backend ----------------------------------------------------
if(LMPFS_BUILD_MOUNT_FUSE)
    if(WIN32)
        message(FATAL_ERROR "FUSE mount only supported on Linux hosts")
    endif()
    target_sources(memnixfs_core PRIVATE src/mount/fuse_mount.cpp)
    target_compile_definitions(memnixfs_core
        PUBLIC LMPFS_HAS_FUSE=1
        PRIVATE FUSE_USE_VERSION=${LMPFS_FUSE_USE_VERSION})
    target_link_libraries(memnixfs_core PUBLIC PkgConfig::FUSE)
endif()

install(TARGETS memnixfs memnixfs_dll
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
if(WIN32)
    install(DIRECTORY "$<TARGET_FILE_DIR:memnixfs>/"
        DESTINATION bin
        FILES_MATCHING PATTERN "*.dll")
endif()
install(FILES README.md vcpkg.json DESTINATION share/memnixfs)
install(DIRECTORY docs DESTINATION share/memnixfs)
install(DIRECTORY tools DESTINATION share/memnixfs OPTIONAL)

set(CPACK_PACKAGE_NAME "MemNixFS")
set(CPACK_PACKAGE_VENDOR "MemNixFS")
set(CPACK_PACKAGE_CONTACT "MemNixFS maintainers")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Mount Linux memory dumps as a virtual filesystem")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "MemNixFS")
set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)
set(CPACK_GENERATOR "TGZ;ZIP")
if(UNIX)
    list(APPEND CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "MemNixFS maintainers")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    find_program(LMPFS_RPMBUILD_EXECUTABLE rpmbuild)
    if(LMPFS_RPMBUILD_EXECUTABLE)
        list(APPEND CPACK_GENERATOR "RPM")
    endif()
endif()
include(CPack)
