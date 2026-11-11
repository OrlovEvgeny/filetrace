cmake_minimum_required(VERSION 3.25)

project(filetrace
    VERSION 0.1.0
    DESCRIPTION "File-to-network observability"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(FILETRACE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(FILETRACE_WERROR "Treat compiler warnings as errors" OFF)

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
target_compile_definitions(ft_build INTERFACE
    FT_VERSION="${PROJECT_VERSION}"
    FT_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
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
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_definitions(ft_build INTERFACE _DARWIN_C_SOURCE)
else()
    target_compile_definitions(ft_build INTERFACE _DEFAULT_SOURCE __BSD_VISIBLE=1)
endif()

# ---------------------------------------------------------------------------
# Platform backend
# ---------------------------------------------------------------------------

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.3)

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

add_library(ft_core STATIC
    core/base.c
    core/capabilities.c
    core/client.c
    core/clock.c
    core/evlog.c
    core/format.c
    core/model.c
    core/query.c
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
    target_link_libraries(ft_backend PRIVATE PkgConfig::LIBBPF)
    target_include_directories(ft_backend SYSTEM PRIVATE ${LIBBPF_INCLUDE_DIRS})
endif()

add_library(ft_daemon STATIC
    daemon/lifecycle.c
    daemon/server.c
)
target_link_libraries(ft_daemon PUBLIC ft_core ft_backend)
target_include_directories(ft_daemon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

add_executable(filetraced daemon/main.c)
target_link_libraries(filetraced PRIVATE ft_daemon)

add_library(ft_cli STATIC
    cmd/args.c
    cmd/diagnostics.c
    cmd/events.c
    cmd/queries.c
    cmd/service.c
    cmd/views.c
    exporters/csv.c
    exporters/json.c
    ui/table.c
    ui/terminal.c
    ui/watch.c
)
target_link_libraries(ft_cli PUBLIC ft_daemon)

add_executable(filetrace cmd/filetrace.c)
target_link_libraries(filetrace PRIVATE ft_cli)

install(TARGETS filetrace filetraced RUNTIME DESTINATION bin)

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
