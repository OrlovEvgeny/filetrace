#ifndef FILETRACE_TUI_SCREEN_H
#define FILETRACE_TUI_SCREEN_H

#include "filetrace/base.h"
#include "ui/tui/canvas.h"
#include "ui/tui/theme.h"

enum ft_key : uint8_t {
    FT_KEY_NONE,
    FT_KEY_CHAR, /* a printable character, in rune */
    FT_KEY_SPACE,
    FT_KEY_ENTER,
    FT_KEY_ESC,
    FT_KEY_TAB,
    FT_KEY_BACKTAB,
    FT_KEY_BACKSPACE,
    FT_KEY_DELETE,
    FT_KEY_INSERT,
    FT_KEY_UP,
    FT_KEY_DOWN,
    FT_KEY_LEFT,
    FT_KEY_RIGHT,
    FT_KEY_HOME,
    FT_KEY_END,
    FT_KEY_PGUP,
    FT_KEY_PGDN,
    FT_KEY_F1,
    FT_KEY_F2,
    FT_KEY_F3,
    FT_KEY_F4,
    FT_KEY_F5,
    FT_KEY_F6,
    FT_KEY_F7,
    FT_KEY_F8,
    FT_KEY_F9,
    FT_KEY_F10,
    FT_KEY_F11,
    FT_KEY_F12,
    /* Ctrl-H, I, J and M arrive as Backspace, Tab and Enter; Ctrl-Z suspends the process. */
    FT_KEY_CTRL_A,
    FT_KEY_CTRL_B,
    FT_KEY_CTRL_C,
    FT_KEY_CTRL_D,
    FT_KEY_CTRL_E,
    FT_KEY_CTRL_F,
    FT_KEY_CTRL_G,
    FT_KEY_CTRL_H,
    FT_KEY_CTRL_I,
    FT_KEY_CTRL_J,
    FT_KEY_CTRL_K,
    FT_KEY_CTRL_L,
    FT_KEY_CTRL_M,
    FT_KEY_CTRL_N,
    FT_KEY_CTRL_O,
    FT_KEY_CTRL_P,
    FT_KEY_CTRL_Q,
    FT_KEY_CTRL_R,
    FT_KEY_CTRL_S,
    FT_KEY_CTRL_T,
    FT_KEY_CTRL_U,
    FT_KEY_CTRL_V,
    FT_KEY_CTRL_W,
    FT_KEY_CTRL_X,
    FT_KEY_CTRL_Y,
    FT_KEY_CTRL_Z,
};

enum ft_mod : uint8_t {
    FT_MOD_SHIFT = 1,
    FT_MOD_ALT = 2,
    FT_MOD_CTRL = 4,
};

enum ft_mouse : uint8_t {
    FT_MOUSE_LEFT,
    FT_MOUSE_MIDDLE,
    FT_MOUSE_RIGHT,
    FT_MOUSE_RELEASE,
    FT_MOUSE_WHEEL_UP,
    FT_MOUSE_WHEEL_DOWN,
};

enum ft_input_kind : uint8_t {
    FT_INPUT_KEY,
    FT_INPUT_MOUSE,
    FT_INPUT_RESIZE, /* also after the process comes back from Ctrl-Z */
};

struct ft_input {
    enum ft_input_kind kind;
    enum ft_key key;
    enum ft_mouse mouse;
    uint8_t mods;  /* enum ft_mod bits */
    uint32_t rune; /* FT_KEY_CHAR and FT_KEY_SPACE */
    int x;         /* the mouse cell */
    int y;
};

enum ft_wait : uint8_t {
    FT_WAIT_TIMEOUT,
    FT_WAIT_INPUT,
    FT_WAIT_WAKE, /* wake_fd is readable; the caller drains it */
    FT_WAIT_QUIT, /* SIGINT, SIGTERM, SIGHUP or SIGQUIT arrived, or the terminal went away */
};

/* One per process. */
struct ft_screen;

/* Takes the terminal; call it before starting threads, as it may set TERM for a moment. */
struct ft_screen *ft_screen_open(enum ft_color_depth depth, struct ft_error *err);
/* Gives the terminal back as it was; safe to call twice, and called at exit. */
void ft_screen_close(struct ft_screen *s);

enum ft_color_depth ft_screen_depth(const struct ft_screen *s);
void ft_screen_size(const struct ft_screen *s, int *cols, int *rows);

/* Shows the canvas; only the cells that changed since the last present are written. */
void ft_screen_present(struct ft_screen *s, const struct ft_canvas *c);
/* Shows the terminal cursor at (x, y) from the next present on; x < 0 hides it. */
void ft_screen_cursor(struct ft_screen *s, int x, int y);

/* Waits up to timeout_ms (< 0: no limit) for input or wake_fd (< 0: none) turning readable. */
enum ft_wait ft_screen_wait(struct ft_screen *s, int timeout_ms, int wake_fd, struct ft_input *in);

/* Puts text on the system clipboard through the terminal (OSC 52). */
void ft_screen_copy(struct ft_screen *s, const char *text);

#endif
