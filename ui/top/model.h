#ifndef FILETRACE_TOP_MODEL_H
#define FILETRACE_TOP_MODEL_H

#include "ui/top/filter.h"
#include "ui/top/top.h"

/*
 * Everything filetrace top knows and decides that is neither drawing nor input: it takes the
 * agent's answers of each refresh and gives, per mode, the ordered rows the screen draws.
 *
 * Pointers it hands out stay valid until the next call that takes a non-const model.
 */
struct ft_top_model;

constexpr size_t FT_TOP_METHODS = FT_METHOD_IO_URING + 1;
constexpr size_t FT_TOP_CONFIDENCES = FT_CONF_EXACT + 1;
constexpr size_t FT_TOP_TREND = 12;                           /* points of a destination's trend */
constexpr uint64_t FT_TOP_TREND_SLOT_NS = 25 * FT_NS_PER_SEC; /* twelve of them make five minutes */
constexpr uint64_t FT_TOP_DONE_NS = 2 * FT_NS_PER_SEC; /* how long a finished selected row stays */

/* The answers of one refresh, all taken at one moment. */
struct ft_top_sample {
    uint64_t mono_ns;                   /* when they were taken, on a monotonic clock */
    const struct ft_row_stats *stats;   /* nullptr when the agent did not answer */
    const struct ft_rows *transfers;    /* FT_MSG_ROW_TRANSFER rows of the active transfers */
    const struct ft_rows *processes;    /* FT_MSG_ROW_PROCESS rows */
    const struct ft_rows *destinations; /* lifetime totals by destination; nullptr: as before */
};

struct ft_top_leaders_sample {
    enum ft_leader_window window;
    enum ft_leader_key key;
    enum ft_top_sort by; /* FT_TOP_SORT_BYTES, _TRANSFERS or _DESTINATIONS */
    const struct ft_row_leader_summary *summary;
    const struct ft_rows *ranking;      /* FT_MSG_ROW_LEADER rows, in rank order */
    const struct ft_rows *directories;  /* top FT_LEADER_DIRECTORY rows, or nullptr */
    const struct ft_rows *destinations; /* top FT_LEADER_DESTINATION rows, or nullptr */
};

enum ft_top_host : uint8_t {
    FT_TOP_HOST_OFF,     /* names are not being resolved */
    FT_TOP_HOST_PENDING, /* the lookup has not finished */
    FT_TOP_HOST_NAMED,
    FT_TOP_HOST_NAMELESS, /* the address has no name */
};

struct ft_top_transfer;

struct ft_top_process {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    bool known; /* reported by the agent; else built from its transfers, or only a pid */
    bool uid_known;
    const char *user; /* the name, or the uid in digits; "" when unknown */
    uint64_t start_wall_ns;
    const char *comm;
    const char *exe;
    const char *command_line;
    const char *cwd;
    const char *script;      /* "" when none */
    const char *script_name; /* base name of script */
    const char *title;       /* "nginx: worker process", "java"; "" for a bare pid */
    const char *name;        /* the title before its ':', "nginx" */
    const char *head;        /* the COMMAND column's bold part: "nginx: worker", "java" */
    const char *rest;        /* the COMMAND column's dim part: the remaining words */

    /* Filled by the Processes mode, from the transfers its filter passes; in the tree with
       every descendant. */
    uint64_t rate;
    uint64_t total; /* file bytes since the agent started */
    uint32_t files;
    uint32_t destinations;
    uint8_t method;     /* the one carrying the most of the rate */
    uint8_t confidence; /* the lowest among the transfers of that method */
    const struct ft_top_transfer *const *transfers; /* its own, by rate */
    size_t ntransfers;
};

struct ft_top_destination {
    struct ft_endpoint address; /* port 0 */
    char text[48];              /* "10.0.5.22", "2001:db8::1" */
    char label[56];             /* "10.0.5.22:45910", or "10.0.5.22:*" over several ports */
    bool is_public;
    bool is_new;                 /* first seen in the last five minutes */
    uint64_t first_seen_wall_ns; /* 0 when it was already active as the model started */
    enum ft_top_host host_state;
    const char *host;             /* when host_state is FT_TOP_HOST_NAMED */
    uint64_t trend[FT_TOP_TREND]; /* bytes per second in each slot, oldest first */
    uint32_t subnet_destinations; /* active ones in its /24 (IPv4) or /64 (IPv6) */

    /* Filled by the Destinations mode, from the transfers its filter passes. */
    uint64_t rate;
    uint64_t total; /* the agent's lifetime count when given, else its transfers' bytes */
    uint32_t files;
    uint32_t processes;
    uint32_t ports;
    uint8_t method;
    uint8_t confidence;
    const struct ft_top_process *top_process;       /* by rate */
    const struct ft_top_transfer *top;              /* by rate; its file is the top file */
    const struct ft_top_transfer *const *transfers; /* by rate */
    size_t ntransfers;
};

struct ft_top_sender {
    const struct ft_top_process *process;
    uint32_t transfers;
    uint64_t rate;
};

struct ft_top_file {
    uint64_t dev;
    uint64_t ino;
    const char *path;     /* as for a transfer */
    uint32_t name_offset; /* where the base name starts in path */
    bool path_known;
    bool deleted;
    uint64_t size;

    /* Filled by the Files mode, from the transfers its filter passes. */
    uint64_t rate;
    uint64_t rate_public;
    double public_share; /* of the rate */
    uint32_t active;     /* transfers */
    uint32_t destinations;
    uint32_t processes;
    const char *senders; /* "nginx ×4", "nginx, php-fpm" */
    uint8_t method;
    uint8_t confidence;
    const struct ft_top_transfer *top;
    const struct ft_top_sender *by_sender; /* by rate */
    size_t nsenders;
    const struct ft_top_transfer *const *transfers; /* by rate */
    size_t ntransfers;
};

struct ft_top_transfer {
    uint64_t id;
    uint32_t pid;
    const struct ft_top_process *process;         /* user, title, command line, cwd */
    const struct ft_top_destination *destination; /* host name, newness */
    const struct ft_top_file *file;
    const char *script;      /* this transfer's, a PHP request's own; "" when none */
    const char *script_name; /* base name of script */
    const char *path;        /* the path, "(device 2049 inode 928371)", or "unknown" */
    uint32_t name_offset;    /* where the base name starts in path */
    bool path_known;
    bool deleted;
    struct ft_endpoint remote;
    char remote_text[56];                /* "10.0.5.22:45910", "[2001:db8::1]:443" */
    const struct ft_remote_names *names; /* of the remote end; nullptr when it has none */
    bool is_public;
    uint64_t rate; /* bytes per second, smoothed; 0 once done */
    uint64_t bytes;
    uint64_t size;   /* of the file when first seen; 0 when unknown */
    double progress; /* bytes / size, at most 1; negative when the size is unknown */
    uint64_t first_wall_ns;
    uint64_t age_ns;    /* at the latest sample */
    uint8_t method;     /* enum ft_method */
    uint8_t confidence; /* enum ft_confidence */
    bool incomplete;    /* events were lost while it was in progress */
    bool done;          /* no longer reported; stays a moment while selected */
};

/* The heading of a group, with its subtotals. */
struct ft_top_section {
    enum ft_top_group by;
    const char *title; /* process title, script, address, directory or subnet; "" for none */
    uint32_t rows;
    uint32_t processes;
    uint32_t files;
    uint32_t destinations;
    uint64_t rate;
};

/* Tree: children of one parent that share a title, beyond the first of them. */
struct ft_top_fold {
    const char *title;
    const char *name;
    const struct ft_top_process *const *members; /* in order */
    size_t count;
    uint64_t rate;
    uint64_t total;
    uint32_t files;
    uint32_t destinations;
    uint8_t method;
};

struct ft_top_leader {
    const struct ft_row_leader *row; /* as the agent sent it */
    uint32_t name_offset;            /* where the base name starts in row->text */
    char remote_text[48];            /* by destination: the address */
    enum ft_top_host host_state;
    const char *host;
    int32_t rank_change; /* previous_rank - rank: positive moved up; 0 when new */
    bool is_new;         /* not among the previous span's first fifty */
    double bar;          /* the ranked value relative to the first row's */
    double share;        /* of the bytes of the whole span */
};

struct ft_top_leaders {
    enum ft_leader_window window;
    enum ft_leader_key key;
    enum ft_top_sort by;
    bool answered; /* an answer to this request has arrived */
    struct ft_row_leader_summary summary;
    double exact_share;   /* of the bytes, moved by the kernel itself */
    double concentration; /* of the bytes, sent by the ten largest files */
    const struct ft_top_leader *directories;
    size_t ndirectories;
    const struct ft_top_leader *destinations;
    size_t ndestinations;
};

/* A meter that shows an amount rather than a share. */
struct ft_top_meter {
    uint64_t value;
    uint64_t scale; /* the full bar: 1, 2 or 5 times a power of ten */
};

/* What the meters and the summary show; of every transfer, whatever the filters. */
struct ft_top_totals {
    uint64_t now_wall_ns;                 /* the agent's clock at the latest sample */
    struct ft_top_meter rate;             /* bytes per second; its scale fits every rate bar */
    struct ft_top_meter started;          /* transfers started per second, smoothed */
    struct ft_top_meter processes;        /* sending */
    struct ft_top_meter files;            /* in flight */
    struct ft_top_meter fanout;           /* the most transfers of one file */
    struct ft_top_meter new_destinations; /* first seen in the last five minutes */
    uint64_t rate_by_method[FT_TOP_METHODS];
    uint64_t rate_exact;
    uint64_t rate_public;
    uint64_t rate_private;
    double exact_share;
    double public_share;
    double sendfile_share;
    uint32_t transfers;
    uint32_t transfers_by_method[FT_TOP_METHODS];
    uint32_t transfers_by_confidence[FT_TOP_CONFIDENCES];
    uint32_t destinations;
    uint32_t destinations_public;
    uint32_t destinations_private;
    bool agent;    /* the latest sample has the agent's statistics */
    bool degraded; /* the agent lost events recently */
    const char *backend;
    uint32_t queue_percent; /* the largest backlog seen, of the queue's capacity */
    uint64_t events_dropped;
    const struct ft_row_stats *stats; /* the rest of them; nullptr without an answer */
};

/* What a mode's status line and badge show. */
struct ft_top_view {
    size_t shown; /* items the filter passed: transfers, processes, destinations, files, leaders */
    size_t total; /* items without the filter */
    size_t matches; /* rows the search matches */
    /* Of the transfers the filter passed: */
    size_t transfers;
    size_t processes;
    size_t files;
    size_t destinations;
    size_t destinations_public;
    size_t scripts;
    uint64_t rate;
};

struct ft_top_sort_option {
    enum ft_top_sort key;
    const char *label; /* as the sort panel lists it */
    bool descending;   /* its default: numbers descend, text ascends */
};

enum ft_top_row_kind : uint8_t {
    FT_TOP_ROW_TRANSFER, /* also under its process in the tree */
    FT_TOP_ROW_PROCESS,
    FT_TOP_ROW_DESTINATION,
    FT_TOP_ROW_FILE,
    FT_TOP_ROW_LEADER,
    FT_TOP_ROW_SECTION,
    FT_TOP_ROW_FOLD,
};

enum ft_top_node : uint8_t {
    FT_TOP_NODE_LEAF,
    FT_TOP_NODE_EXPANDED,
    FT_TOP_NODE_COLLAPSED,
};

#define FT_TOP_ROW_SELECTED 0x01u
#define FT_TOP_ROW_TAGGED 0x02u
#define FT_TOP_ROW_DONE 0x04u
#define FT_TOP_ROW_MATCH 0x08u /* the search finds its text */
#define FT_TOP_ROW_LAST 0x10u  /* tree: the last child of its parent, drawn └─ rather than ├─ */

struct ft_top_row {
    union {
        const void *entity;
        const struct ft_top_transfer *transfer;
        const struct ft_top_process *process;
        const struct ft_top_destination *destination;
        const struct ft_top_file *file;
        const struct ft_top_leader *leader;
        const struct ft_top_section *section;
        const struct ft_top_fold *fold;
    };
    uint32_t rails; /* tree: bit d (1 <= d < depth) when a │ runs down column d */
    enum ft_top_row_kind kind;
    enum ft_top_node node;
    uint8_t depth; /* tree: 0 for a root */
    uint8_t flags; /* FT_TOP_ROW_* */
};

struct ft_top_model *ft_top_model_create(void);
void ft_top_model_destroy(struct ft_top_model *m);

/* False when memory ran out; the model then shows what it had before. */
bool ft_top_model_sample(struct ft_top_model *m, const struct ft_top_sample *s);
bool ft_top_model_leaders(struct ft_top_model *m, const struct ft_top_leaders_sample *s);

/* Lets finished rows go once their time is up; true when rows changed. */
bool ft_top_model_tick(struct ft_top_model *m, uint64_t mono_ns);

/* The mode on screen, rebuilt with every sample; the others when next read. */
void ft_top_set_mode(struct ft_top_model *m, enum ft_top_mode mode);

size_t ft_top_row_count(const struct ft_top_model *m, enum ft_top_mode mode);
const struct ft_top_row *ft_top_row_at(const struct ft_top_model *m, enum ft_top_mode mode,
                                       size_t i);
const struct ft_top_view *ft_top_view_of(const struct ft_top_model *m, enum ft_top_mode mode);
const struct ft_top_totals *ft_top_totals(const struct ft_top_model *m);
const struct ft_top_leaders *ft_top_leaders(const struct ft_top_model *m);

const struct ft_top_sort_option *ft_top_mode_sorts(enum ft_top_mode mode, size_t *count);

/* False when the mode has no such key; FT_TOP_SORT_DEFAULT is the mode's own. */
bool ft_top_set_sort(struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_sort key,
                     bool descending);
void ft_top_sort_of(const struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_sort *key,
                    bool *descending);

/* An empty expression clears it; on an error the filter in effect stays. */
bool ft_top_set_filter(struct ft_top_model *m, enum ft_top_mode mode, const char *expression,
                       struct ft_error *err);
const char *ft_top_filter_of(const struct ft_top_model *m, enum ft_top_mode mode);
const struct ft_top_filter *ft_top_filter_get(const struct ft_top_model *m, enum ft_top_mode mode);

/* Flags the matching rows and selects the first at or after the selection. */
void ft_top_set_search(struct ft_top_model *m, enum ft_top_mode mode, const char *text);
const char *ft_top_search_of(const struct ft_top_model *m, enum ft_top_mode mode);
/* Selects the next (direction > 0) or previous matching row, wrapping; false when none. */
bool ft_top_search_step(struct ft_top_model *m, enum ft_top_mode mode, int direction);

/* Ignored by the tree and by Leaders. */
void ft_top_set_group(struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_group group);
enum ft_top_group ft_top_group_of(const struct ft_top_model *m, enum ft_top_mode mode);

void ft_top_set_tree(struct ft_top_model *m, bool on);
bool ft_top_tree_of(const struct ft_top_model *m);

void ft_top_set_resolve(struct ft_top_model *m, bool on);
bool ft_top_resolve_of(const struct ft_top_model *m);

/* What Leaders shows; its rank order is the Leaders mode's sort key. */
void ft_top_set_leaders_request(struct ft_top_model *m, enum ft_leader_window window,
                                enum ft_leader_key key);

/* The selected row's index, or SIZE_MAX when there are no rows. */
size_t ft_top_selected(const struct ft_top_model *m, enum ft_top_mode mode);
void ft_top_select_by(struct ft_top_model *m, enum ft_top_mode mode, long delta);
/* Past the end selects the last row. */
void ft_top_select_at(struct ft_top_model *m, enum ft_top_mode mode, size_t index);

void ft_top_tag_toggle(struct ft_top_model *m, enum ft_top_mode mode);
void ft_top_tags_clear(struct ft_top_model *m, enum ft_top_mode mode);
size_t ft_top_tag_count(const struct ft_top_model *m, enum ft_top_mode mode);

void ft_top_set_expanded(struct ft_top_model *m, enum ft_top_mode mode, size_t index,
                         bool expanded);
void ft_top_toggle_expanded(struct ft_top_model *m, enum ft_top_mode mode, size_t index);
void ft_top_expand_all(struct ft_top_model *m, enum ft_top_mode mode);

/* "512B", "51K", "38.4M", "2.1G", "1.84T": powers of 1024. */
void ft_top_format_size(uint64_t bytes, char *buf, size_t size);
/* The same with "/s". */
void ft_top_format_rate(uint64_t bytes_per_second, char *buf, size_t size);
/* "0.3s", "21s", "4:57", "1h00", "3d04". */
void ft_top_format_age(uint64_t ns, char *buf, size_t size);
/* " 63%", "100%": four columns; 100% only for a whole. */
void ft_top_format_percent(double share, char *buf, size_t size);

#endif
