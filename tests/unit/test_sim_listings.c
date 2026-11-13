#include "unit/test.h"

#include "cmd/cli.h"
#include "filetrace/state.h"
#include "sim/engine.h"

#include <stdlib.h>

static struct ft_sim_engine *running;

static bool sim_process(uint32_t pid, struct ft_ev_process *out)
{
    return ft_sim_engine_process(running, pid, out);
}

static bool sim_process_text(uint32_t pid, struct ft_process_text *out)
{
    return ft_sim_engine_process_text(running, pid, out);
}

static void ingest(void *ctx, const struct ft_event *ev)
{
    ft_state_ingest(ctx, ev);
}

/* Keeps a row without its wall-clock times, which are read off a clock that two runs see apart. */
static void keep_row(void *ctx, uint16_t type, const void *payload, size_t size)
{
    static union {
        struct ft_row_connection connection;
        struct ft_row_flow flow;
        struct ft_row_transfer transfer;
        struct ft_row_event event;
    } row;
    struct ft_rows *rows = ctx;

    if (type != rows->type)
        return;
    memset(&row, 0, sizeof(row));
    memcpy(&row, payload, size);
    switch (type) {
    case FT_MSG_ROW_CONNECTION:
        row.connection.first_wall_ns = 0;
        row.connection.last_wall_ns = 0;
        row.connection.closed_wall_ns = 0;
        break;
    case FT_MSG_ROW_FLOW:
        row.flow.first_wall_ns = 0;
        row.flow.last_wall_ns = 0;
        break;
    case FT_MSG_ROW_TRANSFER:
        row.transfer.first_wall_ns = 0;
        row.transfer.last_wall_ns = 0;
        break;
    default:
        row.event.time_ns = 0;
        break;
    }
    CHECK(ft_rows_append(rows, &row, size));
}

struct printed {
    char *text;
    size_t size;
};

/*
 * A minute of the simulated host, then everything the listing commands print of it: each table,
 * each JSON line, each CSV line, and the records of the events command as they are sent.
 */
static struct printed listings(bool keep_names, bool emit_names)
{
    static const struct {
        enum ft_query_kind kind;
        uint16_t row;
        enum ft_view_id views[2];
        size_t nviews;
    } lists[] = {
        {FT_Q_CONNECTIONS, FT_MSG_ROW_CONNECTION, {FT_VIEW_CONNECTIONS}, 1},
        {FT_Q_FLOWS, FT_MSG_ROW_FLOW, {FT_VIEW_FLOWS}, 1},
        {FT_Q_TRANSFERS, FT_MSG_ROW_TRANSFER, {FT_VIEW_FILES, FT_VIEW_TRANSFERS}, 2},
    };
    static const enum ft_format formats[] = {FT_FMT_TABLE, FT_FMT_JSONL, FT_FMT_CSV};
    constexpr uint64_t START_NS = 1000 * FT_NS_PER_SEC;
    constexpr uint64_t FLUSH_NS = 250 * FT_NS_PER_MS;
    struct printed out = {0};
    struct ft_state_config cfg;
    struct ft_msg_end end;
    struct ft_error err;
    struct ft_rows rows;
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    cfg.names = keep_names;
    cfg.lookup_process = sim_process;
    cfg.read_process_text = sim_process_text;
    struct ft_state *st = ft_state_create(&cfg);
    struct ft_sim_scenario *scenario = ft_sim_scenario_create("edge", 0);
    struct ft_sink sink = {.ctx = st, .emit = ingest};
    running = ft_sim_engine_create(scenario, 1, START_NS, &sink);
    ft_sim_engine_lose_nothing(running);
    ft_sim_engine_names(running, emit_names, emit_names);
    for (uint64_t t = START_NS + FLUSH_NS; t <= START_NS + 60 * FT_NS_PER_SEC; t += FLUSH_NS)
        ft_sim_engine_run(running, t, 50 * FT_NS_PER_MS);
    uint64_t now = ft_sim_engine_now(running);

    FILE *mem = open_memstream(&out.text, &out.size);
    for (size_t i = 0; i < FT_ARRAY_LEN(lists); i++) {
        ft_query_init(&q, lists[i].kind);
        q.flags = FT_QF_INCLUDE_UNKNOWN;
        ft_rows_init(&rows, lists[i].row);
        CHECK(ft_state_query(st, &q, now, keep_row, &rows, &end, &err));
        CHECK(rows.count > 20);
        for (size_t v = 0; v < lists[i].nviews; v++) {
            for (size_t f = 0; f < FT_ARRAY_LEN(formats); f++) {
                struct ft_output o = {.format = formats[f], .stream = mem};
                ft_view_render(lists[i].views[v], &rows, &o, false);
            }
        }
        ft_rows_free(&rows);
    }
    ft_query_init(&q, FT_Q_EVENTS);
    ft_rows_init(&rows, FT_MSG_ROW_EVENT);
    CHECK(ft_state_query(st, &q, now, keep_row, &rows, &end, &err));
    CHECK(rows.count > 100);
    for (size_t r = 0; r < rows.count; r++) {
        fwrite(&rows.sizes[r], sizeof(rows.sizes[r]), 1, mem);
        fwrite(rows.data + rows.offsets[r], 1, rows.sizes[r], mem);
    }
    ft_rows_free(&rows);
    fclose(mem);

    ft_sim_engine_destroy(running);
    running = nullptr;
    ft_sim_scenario_free(scenario);
    ft_state_destroy(st);
    return out;
}

static bool same(const struct printed *a, const struct printed *b)
{
    return a->size == b->size && memcmp(a->text, b->text, a->size) == 0;
}

static size_t count(const char *text, const char *what)
{
    size_t n = 0;
    for (const char *at = strstr(text, what); at; at = strstr(at + 1, what))
        n++;
    return n;
}

/* Without names kept, or with none to keep, the listings print what they printed before names. */
static void listings_without_names(void)
{
    struct printed before = listings(false, false);
    struct printed off = listings(false, true);
    struct printed none_known = listings(true, false);
    struct printed named = listings(true, true);

    CHECK(before.size > 100000);
    CHECK(same(&off, &before));
    CHECK(same(&none_known, &before));
    CHECK(!same(&named, &before));
    CHECK(strstr(before.text, "NAME") == nullptr);
    CHECK(strstr(before.text, "\"remote_name") == nullptr);
    CHECK(strstr(before.text, "\"resolved_name") == nullptr);
    CHECK(memmem(before.text, before.size, "mirror-1.internal", 17) == nullptr);
    /*
     * The two formats read by position differ from before names, and the same way whether names
     * are kept or not: CSV has their four columns, always, and a raw event its remote_name.
     */
    CHECK_U64(count(before.text, ",remote_name,remote_name_source,resolved_names,"
                                 "resolved_name_count,"),
              2);
    CHECK_U64(count(before.text, ",network.remote_name,network.remote_name_source,"
                                 "network.resolved_names,network.resolved_name_count,"),
              2);
    CHECK_U64(count(before.text, "remote_name"), 8);
    CHECK(strstr(named.text, " mirror-1.internal ") != nullptr);
    CHECK(strstr(named.text, "\"remote_name\":\"mirror-1.internal\"") != nullptr);

    free(before.text);
    free(off.text);
    free(none_known.text);
    free(named.text);
}

void test_sim_listings(void)
{
    listings_without_names();
}
