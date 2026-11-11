# Sets FT_VERSION_STRING and FT_COMMIT_STRING from, in order: the cache
# variables below, the tags of a git checkout, the archive stamp of an exported
# tree, and a placeholder.

set(FILETRACE_VERSION "" CACHE STRING "Version to report instead of the one derived from git")
set(FILETRACE_COMMIT "" CACHE STRING "Commit to report instead of the one read from git")

set(FT_VERSION_STRING "${FILETRACE_VERSION}")
set(FT_COMMIT_STRING "${FILETRACE_COMMIT}")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    if(FT_VERSION_STRING STREQUAL "")
        execute_process(
            COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tools/release/version.sh" current
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE ft_version_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE ft_version_status
        )
        if(ft_version_status EQUAL 0)
            set(FT_VERSION_STRING "${ft_version_output}")
        endif()
    endif()
    if(FT_COMMIT_STRING STREQUAL "")
        execute_process(
            COMMAND git rev-parse --short=12 HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE ft_commit_output
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE ft_commit_status
        )
        if(ft_commit_status EQUAL 0)
            set(FT_COMMIT_STRING "${ft_commit_output}")
        endif()
    endif()
endif()

# `git archive` expands the placeholders in this file; a checkout leaves them as they are.
set(ft_archive_stamp "${CMAKE_CURRENT_SOURCE_DIR}/.git_archival.txt")
if(EXISTS "${ft_archive_stamp}")
    file(STRINGS "${ft_archive_stamp}" ft_archive_lines)
    foreach(line IN LISTS ft_archive_lines)
        if(FT_COMMIT_STRING STREQUAL "" AND line MATCHES "^node: ([0-9a-f]+)$")
            string(SUBSTRING "${CMAKE_MATCH_1}" 0 12 FT_COMMIT_STRING)
        elseif(FT_VERSION_STRING STREQUAL "" AND
               line MATCHES "^describe: v([0-9.]+)-(stable|lts)(-([0-9]+)-g([0-9a-f]+))?$")
            set(FT_VERSION_STRING "${CMAKE_MATCH_1}")
            if(CMAKE_MATCH_4)
                string(APPEND FT_VERSION_STRING "+${CMAKE_MATCH_4}.g${CMAKE_MATCH_5}")
            endif()
        endif()
    endforeach()
endif()

if(FT_VERSION_STRING STREQUAL "")
    set(FT_VERSION_STRING "0.0.0.0+unknown")
endif()
if(FT_COMMIT_STRING STREQUAL "")
    set(FT_COMMIT_STRING "unknown")
endif()

message(STATUS "Filetrace ${FT_VERSION_STRING} (${FT_COMMIT_STRING})")
