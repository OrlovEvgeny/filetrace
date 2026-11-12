cmake_minimum_required(VERSION 3.25)

project(filetrace
    DESCRIPTION "File-to-network observability"
    LANGUAGES C
)

include(cmake/Version.cmake)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(FILETRACE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(FILETRACE_WERROR "Treat compiler warnings as errors" OFF)
option(FILETRACE_STATIC
    "Link third-party libraries statically; on Linux the executables are fully static" OFF)

if(FILETRACE_STATIC AND FILETRACE_SANITIZE)
    message(FATAL_ERROR "FILETRACE_STATIC and FILETRACE_SANITIZE cannot be combined")
endif()

find_package(PkgConfig REQUIRED)

# Defines <target> for the pkg-config module found as <prefix>. A static build
# links the archives by path, because a bare -l<name> prefers a shared library.
function(ft_import_library target prefix)
    add_library(${target} INTERFACE)
    if(NOT FILETRACE_STATIC)
        target_link_libraries(${target} INTERFACE PkgConfig::${prefix})
        return()
    endif()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
    target_include_directories(${target} SYSTEM INTERFACE ${${prefix}_STATIC_INCLUDE_DIRS})
    target_link_options(${target} INTERFACE ${${prefix}_STATIC_LDFLAGS_OTHER})
    foreach(library IN LISTS ${prefix}_STATIC_LIBRARIES)
        find_library(FT_ARCHIVE_${library} NAMES ${library}
            HINTS ${${prefix}_STATIC_LIBRARY_DIRS})
        if(FT_ARCHIVE_${library})
            target_link_libraries(${target} INTERFACE ${FT_ARCHIVE_${library}})
        else()
            target_link_libraries(${target} INTERFACE ${library})
        endif()
    endforeach()
endfunction()

add_library(ft_build INTERFACE)
target_compile_options(ft_build INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wshadow
    -Wstrict-prototypes
    -Wmissing-prototypes
)
target_compile_options(ft_build INTERFACE -fstack-protector-strong)
target_compile_definitions(ft_build INTERFACE FT_BUILD_TYPE="${CMAKE_BUILD_TYPE}")

# Only these sources rebuild when the version changes.
set_property(
    SOURCE
        agent/lifecycle.c
        agent/server.c
        agent/telemetry.c
        cmd/diagnostics.c
        exporters/otlp.c
        rpc/grpc_client.c
    APPEND PROPERTY COMPILE_DEFINITIONS
        FT_VERSION="${FT_VERSION_STRING}"
        FT_COMMIT="${FT_COMMIT_STRING}"
)
target_include_directories(ft_build INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(FILETRACE_WERROR)
    target_compile_options(ft_build INTERFACE -Werror)
endif()
if(FILETRACE_SANITIZE)
    target_compile_options(ft_build INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(ft_build INTERFACE -fsanitize=address,undefined)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(ft_build INTERFACE _GNU_SOURCE)
    target_link_options(ft_build INTERFACE -Wl,-z,relro,-z,now)
    if(FILETRACE_STATIC)
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
        target_link_options(ft_build INTERFACE -static-pie)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_definitions(ft_build INTERFACE _DARWIN_C_SOURCE)
else()
    target_compile_definitions(ft_build INTERFACE _DEFAULT_SOURCE __BSD_VISIBLE=1)
endif()

# ---------------------------------------------------------------------------
# Platform backend
# ---------------------------------------------------------------------------

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.3)
    pkg_get_variable(FT_LIBBPF_INCLUDEDIR libbpf includedir)
    ft_import_library(ft_libbpf LIBBPF)

    find_program(FT_BPF_CLANG NAMES clang REQUIRED)
    find_program(FT_LLVM_STRIP NAMES llvm-strip REQUIRED)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(FT_BPF_ARCH arm64)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        set(FT_BPF_ARCH x86)
    else()
        message(FATAL_ERROR "Unsupported Linux architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    endif()

    set(FT_BPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/backends/linux/bpf)
    set(FT_BPF_OBJECTS)
    foreach(name probes fallback)
        set(object ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
        add_custom_command(
            OUTPUT ${object}
            COMMAND ${FT_BPF_CLANG}
                -std=gnu23 -g -O2 -target bpf -mcpu=v3
                -D__TARGET_ARCH_${FT_BPF_ARCH}
                -Wall -Wextra -Wno-unused-parameter
                -I${FT_BPF_DIR}
                -idirafter ${FT_LIBBPF_INCLUDEDIR}
                -c ${FT_BPF_DIR}/${name}.bpf.c
                -o ${object}
            COMMAND ${FT_LLVM_STRIP} -g ${object}
            DEPENDS
                ${FT_BPF_DIR}/${name}.bpf.c
                ${FT_BPF_DIR}/common.bpf.h
                ${FT_BPF_DIR}/abi.h
                ${FT_BPF_DIR}/kernel_types.h
            COMMENT "Compiling BPF probes: ${name}"
            VERBATIM
        )
        list(APPEND FT_BPF_OBJECTS ${object})
    endforeach()
    add_custom_target(ft_bpf_object DEPENDS ${FT_BPF_OBJECTS})

    set(FT_BACKEND_SOURCES
        backends/linux/loader.c
        backends/linux/background.c
        backends/linux/php.c
        backends/linux/diagnose.c
        backends/linux/procfs.c
    )
    set_source_files_properties(backends/linux/loader.c PROPERTIES
        OBJECT_DEPENDS "${FT_BPF_OBJECTS}"
        COMPILE_DEFINITIONS
            "FT_BPF_TRAMPOLINE_OBJECT=\"${CMAKE_CURRENT_BINARY_DIR}/probes.bpf.o\";FT_BPF_KPROBE_OBJECT=\"${CMAKE_CURRENT_BINARY_DIR}/fallback.bpf.o\""
    )
else()
    set(FT_BACKEND_SOURCES backends/unsupported.c)
endif()

# ---------------------------------------------------------------------------
# Libraries
# ---------------------------------------------------------------------------

pkg_check_modules(PROTOBUF_C REQUIRED IMPORTED_TARGET libprotobuf-c>=1.3)
pkg_check_modules(NGHTTP2 REQUIRED IMPORTED_TARGET libnghttp2>=1.60)
ft_import_library(ft_protobuf_c PROTOBUF_C)
ft_import_library(ft_nghttp2 NGHTTP2)

# Written by `buf generate` from proto/ and the OpenTelemetry module; see buf.gen.yaml.
file(GLOB_RECURSE FT_PROTO_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen/*.pb-c.c)
add_library(ft_proto STATIC ${FT_PROTO_SOURCES})
target_include_directories(ft_proto SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/gen)
target_link_libraries(ft_proto PUBLIC ft_protobuf_c)

add_library(ft_core STATIC
    core/arena.c
    core/base.c
    core/capabilities.c
    core/client.c
    core/clock.c
    core/evlog.c
    core/format.c
    core/leaders.c
    core/metrics.c
    core/model.c
    core/net.c
    core/poller.c
    core/process.c
    core/query.c
    core/scripts.c
    core/state.c
    core/sysinfo.c
    core/table.c
    core/wire.c
)
target_link_libraries(ft_core PUBLIC ft_build)

add_library(ft_backend STATIC backends/backend.c ${FT_BACKEND_SOURCES})
target_link_libraries(ft_backend PUBLIC ft_core)
target_include_directories(ft_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_dependencies(ft_backend ft_bpf_object)
    target_link_libraries(ft_backend PRIVATE ft_libbpf)
    target_include_directories(ft_backend SYSTEM PRIVATE ${LIBBPF_INCLUDE_DIRS})
endif()

add_library(ft_rpc STATIC
    rpc/grpc_client.c
    rpc/grpc_server.c
    rpc/h2.c
)
target_link_libraries(ft_rpc PUBLIC ft_core PRIVATE ft_nghttp2)
target_include_directories(ft_rpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_library(ft_agent STATIC
    agent/api.c
    agent/config.c
    agent/lifecycle.c
    agent/otlp.c
    agent/prometheus.c
    agent/server.c
    agent/telemetry.c
    exporters/otlp.c
    exporters/prometheus.c
)
target_link_libraries(ft_agent PUBLIC ft_core ft_backend ft_rpc ft_proto)
target_include_directories(ft_agent PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

add_executable(filetrace-agent agent/main.c)
target_link_libraries(filetrace-agent PRIVATE ft_agent)

add_library(ft_cli STATIC
    cmd/args.c
    cmd/config.c
    cmd/diagnostics.c
    cmd/events.c
    cmd/inspect.c
    cmd/queries.c
    cmd/resolve.c
    cmd/service.c
    cmd/top.c
    cmd/views.c
    exporters/csv.c
    exporters/json.c
    ui/table.c
    ui/terminal.c
    ui/top/filter.c
    ui/top/model.c
    ui/top/options.c
    ui/top/source.c
    ui/top/top.c
    ui/tui/canvas.c
    ui/tui/lineedit.c
    ui/tui/screen.c
    ui/tui/theme.c
    ui/watch.c
)

# termbox2 is one header that also holds its implementation; this is its translation unit.
add_library(ft_termbox STATIC ui/tui/termbox.c)
target_include_directories(ft_termbox SYSTEM PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/termbox2)
# The attribute width sets the size of the cell colors, so every includer must see the same one.
target_compile_definitions(ft_termbox PUBLIC TB_OPT_ATTR_W=32)
target_compile_options(ft_termbox PRIVATE -w)
find_package(Threads REQUIRED)
target_link_libraries(ft_cli PUBLIC ft_agent Threads::Threads PRIVATE ft_termbox)

add_executable(filetrace cmd/filetrace.c)
target_link_libraries(filetrace PRIVATE ft_cli)

install(TARGETS filetrace filetrace-agent RUNTIME DESTINATION bin)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ft_bench_syscalls benchmarks/syscalls.c)
    target_link_libraries(ft_bench_syscalls PRIVATE ft_build)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
