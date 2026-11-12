#include "ui/top/once.h"

#include "ui/top/document.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int ft_top_once(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt)
{
    (void)s;
    (void)cli;
    (void)opt;
    return FT_EXIT_UNSUPPORTED;
}

static bool ends_with_csv(const char *path)
{
    size_t len = strlen(path);

    return len >= 4 && strcasecmp(path + len - 4, ".csv") == 0;
}

/* Opens a new file beside path, to be renamed over it once it is complete. */
static int create_beside(const char *path, char *temp, size_t size)
{
    static unsigned serial;

    for (int attempt = 0; attempt < 16; attempt++) {
        int len = snprintf(temp, size, "%s.tmp-%ld-%u", path, (long)getpid(), serial++);

        if (len < 0 || (size_t)len >= size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        if (fd >= 0 || errno != EEXIST)
            return fd;
    }
    return -1;
}

static bool write_failed(struct ft_error *err, const char *path, int error)
{
    ft_error_set(err, FT_EXIT_ERROR, "Cannot write %s: %s", path, strerror(error));
    return false;
}

bool ft_top_export(const struct ft_top_model *m, enum ft_top_mode mode, const char *path,
                   size_t *rows, struct ft_error *err)
{
    char temp[PATH_MAX + 32];
    int fd;
    FILE *out;
    int error = 0;

    *rows = 0;
    if (!path || !path[0])
        return write_failed(err, "", ENOENT);
    fd = create_beside(path, temp, sizeof(temp));
    if (fd < 0)
        return write_failed(err, path, errno);
    out = fdopen(fd, "w");
    if (!out) {
        error = errno;
        close(fd);
        unlink(temp);
        return write_failed(err, path, error);
    }

    size_t written = ends_with_csv(path) ? ft_top_write_csv(m, mode, out)
                                         : ft_top_write_document(m, mode, true, out);
    if (fflush(out) != 0 || ferror(out))
        error = errno ? errno : EIO;
    if (fclose(out) != 0 && error == 0)
        error = errno ? errno : EIO;
    if (error == 0 && rename(temp, path) != 0)
        error = errno;
    if (error != 0) {
        unlink(temp);
        return write_failed(err, path, error);
    }
    *rows = written;
    return true;
}
