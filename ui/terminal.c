#include "ui/ui.h"

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_termios;
static bool raw_active;

bool ft_term_styled(FILE *stream)
{
    const char *no_color = getenv("NO_COLOR");
    const char *term = getenv("TERM");

    if (!isatty(fileno(stream)))
        return false;
    if (no_color && no_color[0])
        return false;
    return !(term && strcmp(term, "dumb") == 0);
}

void ft_term_size(int *rows, int *cols)
{
    struct winsize ws;

    *rows = 24;
    *cols = 80;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    }
}

bool ft_term_raw_enter(void)
{
    struct termios raw;

    if (raw_active || tcgetattr(STDIN_FILENO, &saved_termios) != 0)
        return false;
    raw = saved_termios;
    raw.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
        return false;
    raw_active = true;
    return true;
}

void ft_term_raw_leave(void)
{
    if (!raw_active)
        return;
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    raw_active = false;
}
