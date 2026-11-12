#include "ui/top/top.h"

#include "filetrace/clock.h"
#include "ui/top/control.h"
#include "ui/top/once.h"
#include "ui/top/presets.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The shortest time between two presents. */
constexpr uint64_t FRAME_NS = 16 * FT_NS_PER_MS;

struct run {
    struct ft_screen *screen;
    struct ft_canvas *canvas;
    struct ft_top_source *source;
    struct ft_top_controller *c;
    struct ft_top_frame frame;
    struct ft_host_info host;
    enum ft_color_depth depth;
};

static void send_request(struct run *r)
{
    struct ft_top_request *req = malloc(sizeof(*req));

    if (!req)
        return;
    ft_top_control_request(r->c, req);
    ft_top_control_sent(r->c, req, ft_top_source_request(r->source, req));
    free(req);
}

static void draw(struct run *r, bool repaint)
{
    struct ft_top_controller *c = r->c;
    int cols;
    int rows;

    ft_screen_size(r->screen, &cols, &rows);
    if (cols != ft_canvas_cols(r->canvas) || rows != ft_canvas_rows(r->canvas))
        ft_canvas_resize(r->canvas, cols > 0 ? cols : 1, rows > 0 ? rows : 1);
    ft_top_layout(&c->ui, ft_canvas_cols(r->canvas), ft_canvas_rows(r->canvas), &c->layout);
    ft_top_control_clamp(c);
    c->hits.count = 0;

    struct ft_top_draw d = {
        .canvas = r->canvas,
        .depth = r->depth,
        .model = c->model,
        .ui = &c->ui,
        .host = &r->host,
        .hits = &c->hits,
        .cursor_x = -1,
        .cursor_y = -1,
    };
    ft_top_draw(&d);
    ft_screen_cursor(r->screen, d.cursor_x, d.cursor_y);
    if (repaint)
        ft_screen_repaint(r->screen);
    ft_screen_present(r->screen, r->canvas);
}

static int wait_ms(uint64_t now, uint64_t deadline)
{
    if (deadline == UINT64_MAX)
        return -1;
    if (deadline <= now)
        return 0;
    uint64_t ms = (deadline - now + FT_NS_PER_MS - 1) / FT_NS_PER_MS;
    return ms > INT_MAX ? INT_MAX : (int)ms;
}

/* Returns at a quit: a key, a signal or the terminal going away. */
static void loop(struct run *r)
{
    struct ft_top_controller *c = r->c;
    uint64_t drawn_ns = 0;
    bool dirty = true;
    bool repaint = false;

    for (;;) {
        uint64_t now = ft_clock_mono_ns();
        unsigned bits = 0;

        if (dirty && now - drawn_ns >= FRAME_NS) {
            c->now_ns = now;
            ft_top_control_tick(c);
            draw(r, repaint);
            drawn_ns = now;
            dirty = false;
            repaint = false;
        }

        uint64_t deadline = dirty ? drawn_ns + FRAME_NS : ft_top_control_deadline(c);
        struct ft_input in;
        enum ft_wait w =
            ft_screen_wait(r->screen, wait_ms(now, deadline), ft_top_source_fd(r->source), &in);

        /* Inputs that arrive together, a held key or a turn of the wheel, make one frame. */
        while (w == FT_WAIT_INPUT) {
            c->now_ns = ft_clock_mono_ns();
            bits |= ft_top_control(c, &in);
            if (bits & FT_TOP_DO_QUIT)
                return;
            w = ft_screen_wait(r->screen, 0, -1, &in);
        }
        if (w == FT_WAIT_QUIT)
            return;
        c->now_ns = ft_clock_mono_ns();
        if (w == FT_WAIT_WAKE && ft_top_source_take(r->source, &r->frame))
            bits |= ft_top_control_frame(c, &r->frame);
        bits |= ft_top_control_tick(c);
        if (bits & FT_TOP_DO_QUIT)
            return;

        if (bits & FT_TOP_DO_REQUEST)
            send_request(r);
        if (bits & FT_TOP_DO_COPY)
            ft_screen_copy(r->screen, c->copy);
        if (bits & FT_TOP_DO_REPAINT)
            repaint = true;
        if (bits & (FT_TOP_DO_REDRAW | FT_TOP_DO_REPAINT))
            dirty = true;
    }
}

static int start(struct run *r, struct ft_session *s, const struct ft_cli *cli,
                 const struct ft_top_options *opt, struct ft_error *err)
{
    struct ft_top_request *first = malloc(sizeof(*first));
    int cols;
    int rows;

    r->depth = ft_color_depth_detect((enum ft_color_mode)opt->color);
    r->screen = ft_screen_open(r->depth, err);
    if (!r->screen) {
        free(first);
        return err->code;
    }
    r->depth = ft_screen_depth(r->screen);
    ft_screen_size(r->screen, &cols, &rows);
    r->canvas = ft_canvas_create(cols > 0 ? cols : 1, rows > 0 ? rows : 1);
    if (!first || !r->canvas) {
        free(first);
        return ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
    }
    r->c->now_ns = ft_clock_mono_ns();
    ft_top_control_request(r->c, first);
    r->source = ft_top_source_start(s, cli, first, err);
    if (r->source) {
        ft_top_control_sent(r->c, first, 1);
        ft_top_control_start(r->c, s->collector > 0);
    }
    free(first);
    return r->source ? FT_EXIT_OK : err->code;
}

int ft_top_run(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt)
{
    struct run r = {0};
    struct ft_error err = {0};
    struct ft_top_model *model = nullptr;
    char *filter = nullptr;
    int code = FT_EXIT_OK;

    if (opt->once || opt->json)
        return ft_top_once(s, cli, opt);

    ft_top_frame_init(&r.frame);
    ft_sysinfo_host(&r.host);
    filter = ft_top_presets_expand(opt->filter ? opt->filter : "", &err);
    if (!filter)
        code = err.code;
    if (code == FT_EXIT_OK) {
        model = ft_top_model_create();
        r.c = calloc(1, sizeof(*r.c));
        if (!model || !r.c)
            code = ft_error_set(&err, FT_EXIT_ERROR, "Out of memory");
    }
    if (code == FT_EXIT_OK && !ft_top_control_init(r.c, model, opt, filter, &err))
        code = err.code;
    if (code == FT_EXIT_OK)
        code = start(&r, s, cli, opt, &err);
    if (code == FT_EXIT_OK)
        loop(&r);
    bool failed = code == FT_EXIT_OK && r.c->exit_code != FT_EXIT_OK;
    if (failed)
        code = ft_error_set(&err, r.c->exit_code, "%s", r.c->ui.agent_error);

    ft_top_source_stop(r.source);
    ft_screen_close(r.screen);
    ft_canvas_destroy(r.canvas);
    ft_top_frame_free(&r.frame);
    if (r.c)
        ft_top_control_free(r.c);
    free(r.c);
    ft_top_model_destroy(model);
    free(filter);

    if (failed)
        return ft_session_failed(cli, code, err.msg);
    if (code == FT_EXIT_USAGE)
        ft_usage_error("top", "%s", err.msg);
    else if (code != FT_EXIT_OK)
        fprintf(stderr, "filetrace: %s\n", err.msg);
    return code;
}
