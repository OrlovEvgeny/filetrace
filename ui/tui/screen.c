#include "ui/tui/screen.h"

#include "termbox2.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Button presses and the wheel in SGR encoding, without motion reports. */
static const char MOUSE_ON[] = "\x1b[?1000h\x1b[?1006h";

/* What termbox2 sends when it lets go, for a signal handler that cannot call it. */
static const char LEAVE[] = "\x1b[?1006l\x1b[?1015l\x1b[?1002l\x1b[?1000l"
                            "\x1b[0m\x1b[?25h\x1b[?1049l\x1b[?1l\x1b>";

/* How soon the bytes after Esc must follow to belong to one escape sequence. */
constexpr int SEQUENCE_MS = 20;

static const int quit_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
static const int crash_signals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};

struct cell_colors {
    uintattr_t fg;
    uintattr_t bg;
};

struct ft_screen {
    enum ft_color_depth depth;
    bool open;
    bool hangup;
    int cursor_x;
    int cursor_y;
    bool has_pending;
    struct tb_event pending;
    struct cell_colors colors[FT_COLOR_COUNT][FT_COLOR_COUNT][8];
};

static struct ft_screen screen;

static volatile sig_atomic_t quit_signal;
static volatile sig_atomic_t stop_signal;
static volatile sig_atomic_t cont_signal;
static volatile sig_atomic_t terminal_taken;
static int signal_pipe[2] = {-1, -1};
static struct termios original_termios;
static struct sigaction saved_quit[FT_ARRAY_LEN(quit_signals)];
static struct sigaction saved_crash[FT_ARRAY_LEN(crash_signals)];
static struct sigaction saved_stop;
static struct sigaction saved_cont;

static void wake_waiter(void)
{
    char byte = 0;
    ssize_t n = write(signal_pipe[1], &byte, 1);

    (void)n;
}

static void restore_from_handler(void)
{
    if (!terminal_taken)
        return;
    terminal_taken = 0;
    ssize_t n = write(STDOUT_FILENO, LEAVE, sizeof(LEAVE) - 1);
    (void)n;
    tcsetattr(STDIN_FILENO, TCSANOW, &original_termios);
}

static void on_quit(int signo)
{
    int saved = errno;

    /* A second request means the loop is not answering: give the terminal back and go. */
    if (quit_signal) {
        restore_from_handler();
        signal(signo, SIG_DFL);
        raise(signo);
    }
    quit_signal = signo;
    wake_waiter();
    errno = saved;
}

static void on_crash(int signo)
{
    restore_from_handler();
    for (size_t i = 0; i < FT_ARRAY_LEN(crash_signals); i++) {
        if (crash_signals[i] == signo)
            sigaction(signo, &saved_crash[i], nullptr);
    }
    raise(signo);
}

static void on_stop(int signo)
{
    int saved = errno;

    (void)signo;
    stop_signal = 1;
    wake_waiter();
    errno = saved;
}

static void on_cont(int signo)
{
    int saved = errno;

    (void)signo;
    cont_signal = 1;
    wake_waiter();
    errno = saved;
}

static void catch_signal(int signo, void (*handler)(int), struct sigaction *saved)
{
    struct sigaction sa = {.sa_handler = handler, .sa_flags = SA_RESTART};

    sigemptyset(&sa.sa_mask);
    sigaction(signo, &sa, saved);
}

static void install_handlers(void)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(quit_signals); i++) {
        catch_signal(quit_signals[i], on_quit, &saved_quit[i]);
        /* A signal ignored when the process started, as under nohup, stays ignored. */
        if (saved_quit[i].sa_handler == SIG_IGN)
            sigaction(quit_signals[i], &saved_quit[i], nullptr);
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(crash_signals); i++)
        catch_signal(crash_signals[i], on_crash, &saved_crash[i]);
    catch_signal(SIGTSTP, on_stop, &saved_stop);
    catch_signal(SIGCONT, on_cont, &saved_cont);
}

static void uninstall_handlers(void)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(quit_signals); i++)
        sigaction(quit_signals[i], &saved_quit[i], nullptr);
    for (size_t i = 0; i < FT_ARRAY_LEN(crash_signals); i++)
        sigaction(crash_signals[i], &saved_crash[i], nullptr);
    sigaction(SIGTSTP, &saved_stop, nullptr);
    sigaction(SIGCONT, &saved_cont, nullptr);
}

static bool open_signal_pipe(void)
{
    if (pipe(signal_pipe) != 0)
        return false;
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(signal_pipe[i], F_GETFL);
        fcntl(signal_pipe[i], F_SETFL, flags | O_NONBLOCK);
        fcntl(signal_pipe[i], F_SETFD, FD_CLOEXEC);
    }
    return true;
}

static void close_signal_pipe(void)
{
    for (int i = 0; i < 2; i++) {
        if (signal_pipe[i] >= 0)
            close(signal_pipe[i]);
        signal_pipe[i] = -1;
    }
}

static void drain_signal_pipe(void)
{
    char buf[64];

    while (read(signal_pipe[0], buf, sizeof(buf)) > 0)
        ;
}

static uintattr_t termbox_color(enum ft_color_depth depth, struct ft_term_color c)
{
    switch (c.kind) {
    case FT_TERM_DEFAULT:
        return TB_DEFAULT;
    case FT_TERM_RGB:
        /* 0 is TB_DEFAULT to termbox2, so black needs its own bit. */
        return c.value ? c.value : TB_HI_BLACK;
    case FT_TERM_INDEX:
        break;
    }
    if (depth == FT_DEPTH_256)
        return c.value ? c.value : TB_HI_BLACK;
    return c.value < 8 ? TB_BLACK + c.value : (TB_BLACK + c.value - 8) | TB_BRIGHT;
}

static void build_colors(struct ft_screen *s)
{
    for (int fg = 0; fg < FT_COLOR_COUNT; fg++) {
        for (int bg = 0; bg < FT_COLOR_COUNT; bg++) {
            for (uint8_t attrs = 0; attrs < 8; attrs++) {
                struct ft_term_style t =
                    ft_theme_resolve(s->depth, (enum ft_color)fg, (enum ft_color)bg, attrs);
                uintattr_t f = termbox_color(s->depth, t.fg);
                if (t.attrs & FT_ATTR_BOLD)
                    f |= TB_BOLD;
                if (t.attrs & FT_ATTR_UNDERLINE)
                    f |= TB_UNDERLINE;
                if (t.attrs & FT_ATTR_REVERSE)
                    f |= TB_REVERSE;
                if (t.attrs & FT_TERM_DIM)
                    f |= TB_DIM;
                s->colors[fg][bg][attrs] = (struct cell_colors){f, termbox_color(s->depth, t.bg)};
            }
        }
    }
}

static int init_termbox(void)
{
    int rv = tb_init_rwfd(STDIN_FILENO, STDOUT_FILENO);
    const char *term = getenv("TERM");

    if ((rv != TB_ERR_UNSUPPORTED_TERM && rv != TB_ERR_NO_TERM) ||
        (term && strcmp(term, "dumb") == 0))
        return rv;

    /* Without terminfo for TERM, xterm's sequences built into termbox2 suit most terminals. */
    char *saved = term ? strdup(term) : nullptr;
    if (term && !saved)
        return TB_ERR_MEM;
    setenv("TERM", "xterm-256color", 1);
    rv = tb_init_rwfd(STDIN_FILENO, STDOUT_FILENO);
    if (saved)
        setenv("TERM", saved, 1);
    else
        unsetenv("TERM");
    free(saved);
    return rv;
}

static bool enter(struct ft_screen *s, struct ft_error *err)
{
    static const int modes[] = {
        [FT_DEPTH_NONE] = TB_OUTPUT_NORMAL,
        [FT_DEPTH_16] = TB_OUTPUT_NORMAL,
        [FT_DEPTH_256] = TB_OUTPUT_256,
        [FT_DEPTH_TRUECOLOR] = TB_OUTPUT_TRUECOLOR,
    };
    struct cell_colors blank = s->colors[FT_COLOR_TEXT][FT_COLOR_BG][0];

    terminal_taken = 1;
    int rv = init_termbox();
    if (rv != TB_OK) {
        terminal_taken = 0;
        ft_error_set(err, FT_EXIT_ERROR, "Cannot take over the terminal: %s", tb_strerror(rv));
        return false;
    }
    tb_set_output_mode(modes[s->depth]);
    tb_set_input_mode(TB_INPUT_ESC);
    tb_set_clear_attrs(blank.fg, blank.bg);
    tb_send(MOUSE_ON, sizeof(MOUSE_ON) - 1);
    if (s->cursor_x >= 0)
        tb_set_cursor(s->cursor_x, s->cursor_y);
    s->has_pending = false;
    s->hangup = false;
    return true;
}

static void leave(void)
{
    if (terminal_taken)
        tb_shutdown();
    terminal_taken = 0;
}

/* Leaves the terminal to the shell for Ctrl-Z, or takes it again after SIGCONT. */
static bool come_back(struct ft_screen *s)
{
    bool stop = stop_signal;

    stop_signal = 0;
    leave();
    if (stop) {
        struct sigaction ours;
        struct sigaction dfl = {.sa_handler = SIG_DFL};
        sigemptyset(&dfl.sa_mask);
        sigaction(SIGTSTP, &dfl, &ours);
        kill(0, SIGTSTP);
        sigaction(SIGTSTP, &ours, nullptr);
    }
    cont_signal = 0;
    return enter(s, nullptr);
}

static void close_at_exit(void)
{
    ft_screen_close(&screen);
}

struct ft_screen *ft_screen_open(enum ft_color_depth depth, struct ft_error *err)
{
    static bool exit_hook;
    struct ft_screen *s = &screen;

    if (s->open) {
        ft_error_set(err, FT_EXIT_ERROR, "The terminal is already taken");
        return nullptr;
    }
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        ft_error_set(err, FT_EXIT_ERROR, "Standard input and output must be a terminal");
        return nullptr;
    }
    if (tcgetattr(STDIN_FILENO, &original_termios) != 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot read the terminal settings: %s", strerror(errno));
        return nullptr;
    }
    if (!open_signal_pipe()) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot create a pipe: %s", strerror(errno));
        return nullptr;
    }

    if (depth > FT_DEPTH_TRUECOLOR)
        depth = FT_DEPTH_16;
    *s = (struct ft_screen){.depth = depth, .cursor_x = -1, .cursor_y = -1};
    build_colors(s);
    quit_signal = 0;
    stop_signal = 0;
    cont_signal = 0;
    install_handlers();
    if (!exit_hook)
        exit_hook = atexit(close_at_exit) == 0;
    if (!enter(s, err)) {
        uninstall_handlers();
        close_signal_pipe();
        return nullptr;
    }
    s->open = true;
    return s;
}

void ft_screen_close(struct ft_screen *s)
{
    if (!s || !s->open)
        return;
    leave();
    uninstall_handlers();
    close_signal_pipe();
    s->open = false;
}

enum ft_color_depth ft_screen_depth(const struct ft_screen *s)
{
    return s->depth;
}

void ft_screen_size(const struct ft_screen *s, int *cols, int *rows)
{
    int w = s->open && terminal_taken ? tb_width() : 0;
    int h = s->open && terminal_taken ? tb_height() : 0;

    *cols = w > 0 ? w : 0;
    *rows = h > 0 ? h : 0;
}

void ft_screen_present(struct ft_screen *s, const struct ft_canvas *c)
{
    if (!s->open || !terminal_taken)
        return;

    int w = tb_width();
    int h = tb_height();
    int cols = ft_canvas_cols(c) < w ? ft_canvas_cols(c) : w;
    int rows = ft_canvas_rows(c) < h ? ft_canvas_rows(c) : h;

    if (cols < w || rows < h)
        tb_clear();
    for (int y = 0; y < rows; y++) {
        for (int x = 0; x < cols; x++) {
            const struct ft_cell *cell = ft_canvas_at(c, x, y);
            if (cell->rune == 0)
                continue;
            int fg = cell->fg < FT_COLOR_COUNT ? cell->fg : FT_COLOR_DEFAULT;
            int bg = cell->bg < FT_COLOR_COUNT ? cell->bg : FT_COLOR_DEFAULT;
            struct cell_colors p = s->colors[fg][bg][cell->attrs & 7];
            tb_set_cell(x, y, cell->rune, p.fg, p.bg);
        }
    }
    tb_present();
}

void ft_screen_repaint(struct ft_screen *s)
{
    if (s->open && terminal_taken)
        tb_invalidate();
}

void ft_screen_cursor(struct ft_screen *s, int x, int y)
{
    s->cursor_x = x < 0 ? -1 : x;
    s->cursor_y = y;
    if (!s->open || !terminal_taken)
        return;
    if (x < 0)
        tb_hide_cursor();
    else
        tb_set_cursor(x, y);
}

static int take_event(struct ft_screen *s, struct tb_event *ev, int timeout_ms)
{
    if (s->has_pending) {
        *ev = s->pending;
        s->has_pending = false;
        return TB_OK;
    }
    return tb_peek_event(ev, timeout_ms);
}

static void put_back(struct ft_screen *s, const struct tb_event *ev)
{
    s->pending = *ev;
    s->has_pending = true;
}

static uint8_t mods_of(uint8_t mod)
{
    uint8_t mods = 0;

    if (mod & TB_MOD_SHIFT)
        mods |= FT_MOD_SHIFT;
    if (mod & TB_MOD_ALT)
        mods |= FT_MOD_ALT;
    if (mod & TB_MOD_CTRL)
        mods |= FT_MOD_CTRL;
    return mods;
}

static bool key_input(const struct tb_event *ev, struct ft_input *in)
{
    static const struct {
        uint16_t tb;
        enum ft_key key;
    } named[] = {
        {TB_KEY_INSERT, FT_KEY_INSERT},    {TB_KEY_DELETE, FT_KEY_DELETE},
        {TB_KEY_HOME, FT_KEY_HOME},        {TB_KEY_END, FT_KEY_END},
        {TB_KEY_PGUP, FT_KEY_PGUP},        {TB_KEY_PGDN, FT_KEY_PGDN},
        {TB_KEY_ARROW_UP, FT_KEY_UP},      {TB_KEY_ARROW_DOWN, FT_KEY_DOWN},
        {TB_KEY_ARROW_LEFT, FT_KEY_LEFT},  {TB_KEY_ARROW_RIGHT, FT_KEY_RIGHT},
        {TB_KEY_BACK_TAB, FT_KEY_BACKTAB},
    };

    *in = (struct ft_input){.kind = FT_INPUT_KEY};
    if (ev->key == 0) {
        if (ev->ch == ' ') {
            in->key = FT_KEY_SPACE;
            in->rune = ' ';
            return true;
        }
        if (tb_wcwidth(ev->ch) < 1)
            return false;
        in->key = FT_KEY_CHAR;
        in->rune = ev->ch;
        return true;
    }

    switch (ev->key) {
    case TB_KEY_ENTER:
    case TB_KEY_CTRL_J:
        in->key = FT_KEY_ENTER;
        return true;
    case TB_KEY_TAB:
        in->key = FT_KEY_TAB;
        return true;
    case TB_KEY_BACKSPACE:
    case TB_KEY_BACKSPACE2:
        in->key = FT_KEY_BACKSPACE;
        return true;
    case TB_KEY_ESC:
        in->key = FT_KEY_ESC;
        return true;
    default:
        break;
    }
    if (ev->key >= TB_KEY_CTRL_A && ev->key <= TB_KEY_CTRL_Z) {
        in->key = (enum ft_key)(FT_KEY_CTRL_A + (ev->key - TB_KEY_CTRL_A));
        in->mods = FT_MOD_CTRL;
        return true;
    }

    in->mods = mods_of(ev->mod);
    if (ev->key <= TB_KEY_F1 && ev->key >= TB_KEY_F12) {
        in->key = (enum ft_key)(FT_KEY_F1 + (TB_KEY_F1 - ev->key));
        return true;
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(named); i++) {
        if (named[i].tb == ev->key) {
            in->key = named[i].key;
            return true;
        }
    }
    return false;
}

static bool is_printable_byte(const struct tb_event *ev)
{
    return ev->type == TB_EVENT_KEY && ev->key == 0 && ev->ch >= 0x20 && ev->ch < 0x7f;
}

/* The common encodings of keys in CSI (intro '[') and SS3 (intro 'O') sequences. */
static bool decode_sequence(char intro, const char *seq, size_t n, struct ft_input *in)
{
    static const struct {
        char final;
        enum ft_key key;
    } letters[] = {
        {'A', FT_KEY_UP},   {'B', FT_KEY_DOWN}, {'C', FT_KEY_RIGHT},   {'D', FT_KEY_LEFT},
        {'H', FT_KEY_HOME}, {'F', FT_KEY_END},  {'P', FT_KEY_F1},      {'Q', FT_KEY_F2},
        {'R', FT_KEY_F3},   {'S', FT_KEY_F4},   {'Z', FT_KEY_BACKTAB}, {'M', FT_KEY_ENTER},
    };
    static const enum ft_key tilde[] = {
        [1] = FT_KEY_HOME, [2] = FT_KEY_INSERT, [3] = FT_KEY_DELETE, [4] = FT_KEY_END,
        [5] = FT_KEY_PGUP, [6] = FT_KEY_PGDN,   [7] = FT_KEY_HOME,   [8] = FT_KEY_END,
        [11] = FT_KEY_F1,  [12] = FT_KEY_F2,    [13] = FT_KEY_F3,    [14] = FT_KEY_F4,
        [15] = FT_KEY_F5,  [17] = FT_KEY_F6,    [18] = FT_KEY_F7,    [19] = FT_KEY_F8,
        [20] = FT_KEY_F9,  [21] = FT_KEY_F10,   [23] = FT_KEY_F11,   [24] = FT_KEY_F12,
    };
    char final = seq[n - 1];
    int params[2] = {0, 0};
    size_t count = 0;

    /* The Linux console sends F1 to F5 as ESC [ [ A to ESC [ [ E. */
    if (intro == '[' && n == 2 && seq[0] == '[') {
        if (final < 'A' || final > 'E')
            return false;
        in->key = (enum ft_key)(FT_KEY_F1 + (final - 'A'));
        return true;
    }
    for (size_t i = 0; i + 1 < n; i++) {
        if (seq[i] >= '0' && seq[i] <= '9' && params[count] < 1000)
            params[count] = params[count] * 10 + (seq[i] - '0');
        else if (seq[i] == ';' && count == 0)
            count = 1;
        else
            return false;
    }
    /* xterm's second parameter is 1 + 1 for Shift + 2 for Alt + 4 for Ctrl. */
    if (params[1] > 1) {
        int m = params[1] - 1;
        in->mods = (uint8_t)((m & 1 ? FT_MOD_SHIFT : 0) | (m & 2 ? FT_MOD_ALT : 0) |
                             (m & 4 ? FT_MOD_CTRL : 0));
    }

    if (final == '~') {
        if (intro != '[' || params[0] <= 0 || (size_t)params[0] >= FT_ARRAY_LEN(tilde) ||
            tilde[params[0]] == FT_KEY_NONE)
            return false;
        in->key = tilde[params[0]];
        return true;
    }
    if (params[0] > 1 || (final == 'M' && intro != 'O'))
        return false;
    for (size_t i = 0; i < FT_ARRAY_LEN(letters); i++) {
        if (letters[i].final == final) {
            in->key = letters[i].key;
            return true;
        }
    }
    return false;
}

/*
 * What an Esc means given the bytes that follow it at once: Esc itself, Alt with a key, or
 * a sequence termbox2 did not decode; false for a sequence nobody knows, which is dropped.
 */
static bool after_escape(struct ft_screen *s, struct ft_input *in)
{
    struct tb_event next;
    struct ft_input alt;
    char seq[16];
    size_t n = 0;
    bool complete = false;

    *in = (struct ft_input){.kind = FT_INPUT_KEY, .key = FT_KEY_ESC};
    if (take_event(s, &next, SEQUENCE_MS) != TB_OK)
        return true;
    if (next.type != TB_EVENT_KEY || next.key != 0) {
        put_back(s, &next);
        return true;
    }
    if (next.ch != '[' && next.ch != 'O') {
        if (key_input(&next, &alt)) {
            *in = alt;
            in->mods |= FT_MOD_ALT;
        }
        return true;
    }

    char intro = (char)next.ch;
    while (!complete && take_event(s, &next, SEQUENCE_MS) == TB_OK) {
        if (!is_printable_byte(&next)) {
            put_back(s, &next);
            break;
        }
        char c = (char)next.ch;
        if (n < sizeof(seq))
            seq[n++] = c;
        complete = c >= 0x40 && !(n == 1 && c == '[');
    }
    if (n == 0) {
        *in = (struct ft_input){
            .kind = FT_INPUT_KEY,
            .key = FT_KEY_CHAR,
            .rune = (uint32_t)intro,
            .mods = FT_MOD_ALT,
        };
        return true;
    }
    *in = (struct ft_input){.kind = FT_INPUT_KEY};
    return complete && n < sizeof(seq) && decode_sequence(intro, seq, n, in);
}

static bool mouse_input(const struct tb_event *ev, struct ft_input *in)
{
    static const struct {
        uint16_t tb;
        enum ft_mouse mouse;
    } buttons[] = {
        {TB_KEY_MOUSE_LEFT, FT_MOUSE_LEFT},         {TB_KEY_MOUSE_MIDDLE, FT_MOUSE_MIDDLE},
        {TB_KEY_MOUSE_RIGHT, FT_MOUSE_RIGHT},       {TB_KEY_MOUSE_RELEASE, FT_MOUSE_RELEASE},
        {TB_KEY_MOUSE_WHEEL_UP, FT_MOUSE_WHEEL_UP}, {TB_KEY_MOUSE_WHEEL_DOWN, FT_MOUSE_WHEEL_DOWN},
    };

    if (ev->mod & TB_MOD_MOTION)
        return false;
    for (size_t i = 0; i < FT_ARRAY_LEN(buttons); i++) {
        if (buttons[i].tb == ev->key) {
            *in = (struct ft_input){
                .kind = FT_INPUT_MOUSE,
                .mouse = buttons[i].mouse,
                .mods = mods_of(ev->mod),
                .x = ev->x,
                .y = ev->y,
            };
            return true;
        }
    }
    return false;
}

enum taken : uint8_t {
    TAKEN_NOTHING,
    TAKEN_INPUT,
    TAKEN_SKIPPED,
    TAKEN_GONE,
};

static enum taken take_input(struct ft_screen *s, struct ft_input *in)
{
    struct tb_event ev;
    struct tb_event next;
    int rv = take_event(s, &ev, 0);

    if (rv == TB_ERR_READ)
        return TAKEN_GONE;
    if (rv != TB_OK)
        return TAKEN_NOTHING;

    switch (ev.type) {
    case TB_EVENT_RESIZE:
        while (take_event(s, &next, 0) == TB_OK) {
            if (next.type != TB_EVENT_RESIZE) {
                put_back(s, &next);
                break;
            }
        }
        *in = (struct ft_input){.kind = FT_INPUT_RESIZE};
        return TAKEN_INPUT;
    case TB_EVENT_MOUSE:
        return mouse_input(&ev, in) ? TAKEN_INPUT : TAKEN_SKIPPED;
    case TB_EVENT_KEY:
        if (ev.key == TB_KEY_CTRL_Z) {
            stop_signal = 1;
            return TAKEN_SKIPPED;
        }
        if (ev.key == TB_KEY_ESC)
            return after_escape(s, in) ? TAKEN_INPUT : TAKEN_SKIPPED;
        return key_input(&ev, in) ? TAKEN_INPUT : TAKEN_SKIPPED;
    default:
        return TAKEN_SKIPPED;
    }
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1'000'000;
}

enum ft_wait ft_screen_wait(struct ft_screen *s, int timeout_ms, int wake_fd, struct ft_input *in)
{
    uint64_t deadline = timeout_ms > 0 ? now_ms() + (uint64_t)timeout_ms : 0;

    if (!s->open)
        return FT_WAIT_QUIT;
    for (;;) {
        if (quit_signal)
            return FT_WAIT_QUIT;
        if (stop_signal || cont_signal || !terminal_taken) {
            if (!come_back(s))
                return FT_WAIT_QUIT;
            *in = (struct ft_input){.kind = FT_INPUT_RESIZE};
            return FT_WAIT_INPUT;
        }

        switch (take_input(s, in)) {
        case TAKEN_INPUT:
            return FT_WAIT_INPUT;
        case TAKEN_SKIPPED:
            continue;
        case TAKEN_GONE:
            return FT_WAIT_QUIT;
        case TAKEN_NOTHING:
            break;
        }
        if (s->hangup)
            return FT_WAIT_QUIT;

        int wait = -1;
        if (timeout_ms >= 0) {
            uint64_t now = now_ms();
            if (timeout_ms == 0 || now >= deadline)
                return FT_WAIT_TIMEOUT;
            wait = (int)(deadline - now);
        }

        int tty = -1;
        int resize = -1;
        tb_get_fds(&tty, &resize);
        struct pollfd fds[4] = {
            {.fd = tty, .events = POLLIN},
            {.fd = resize, .events = POLLIN},
            {.fd = signal_pipe[0], .events = POLLIN},
            {.fd = wake_fd, .events = POLLIN},
        };
        int ready = poll(fds, wake_fd >= 0 ? 4 : 3, wait);
        if (ready < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return FT_WAIT_QUIT;
        }
        if (fds[2].revents)
            drain_signal_pipe();
        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            s->hangup = true;
        if (wake_fd >= 0 && fds[3].revents && !(fds[0].revents & POLLIN) &&
            !(fds[1].revents & POLLIN))
            return FT_WAIT_WAKE;
    }
}

void ft_screen_copy(struct ft_screen *s, const char *text)
{
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *p = (const unsigned char *)text;
    size_t len = strlen(text);
    char chunk[256];
    size_t n = 0;

    if (!s->open || !terminal_taken)
        return;
    tb_send("\x1b]52;c;", 7);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16;
        if (i + 1 < len)
            v |= (uint32_t)p[i + 1] << 8;
        if (i + 2 < len)
            v |= p[i + 2];
        chunk[n++] = digits[v >> 18 & 63];
        chunk[n++] = digits[v >> 12 & 63];
        chunk[n++] = i + 1 < len ? digits[v >> 6 & 63] : '=';
        chunk[n++] = i + 2 < len ? digits[v & 63] : '=';
        if (n + 4 > sizeof(chunk)) {
            tb_send(chunk, n);
            n = 0;
        }
    }
    tb_send(chunk, n);
    tb_send("\a", 1);
    tb_present();
}
