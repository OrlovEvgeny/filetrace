#ifndef FILETRACE_PROCESS_H
#define FILETRACE_PROCESS_H

#include "filetrace/model.h"

/* A process's arguments as the kernel keeps them, and its working directory. */
struct ft_process_text {
    char args[FT_CMDLINE_MAX]; /* each argument followed by a NUL */
    size_t args_len;
    char cwd[FT_PATH_MAX]; /* empty when it cannot be read */
};

/*
 * The arguments joined by spaces, control characters turned into spaces and trailing blanks
 * dropped. Without arguments only the program is kept: the first argument up to its first space.
 */
size_t ft_command_line(const char *args, size_t len, bool arguments, char *out, size_t size);

/*
 * What an interpreter runs, from its arguments: the path of its script resolved against cwd,
 * "module:<name>" for python -m, or "pool:<name>" for a PHP-FPM worker. args holds len bytes and
 * a terminator. Returns false when there is no such thing.
 */
bool ft_script_derive(const char *exe, const char *args, size_t len, const char *cwd, char *out,
                      size_t size);

#endif
