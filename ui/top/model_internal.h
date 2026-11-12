#ifndef FILETRACE_TOP_MODEL_INTERNAL_H
#define FILETRACE_TOP_MODEL_INTERNAL_H

#include "ui/top/model.h"

/* Shared by model.c, which takes the samples, and rows.c, which builds each mode's rows. */

constexpr uint32_t FT_TOP_NONE = UINT32_MAX;

enum ft_top_key_kind : uint32_t {
    FT_TOP_KEY_EMPTY = 0, /* marks a free map slot */
    FT_TOP_KEY_TRANSFER,
    FT_TOP_KEY_PROCESS,
    FT_TOP_KEY_DESTINATION,
    FT_TOP_KEY_FILE,
    FT_TOP_KEY_SECTION,
    FT_TOP_KEY_FOLD,
    FT_TOP_KEY_LEADER,
    FT_TOP_KEY_SUBNET,
    FT_TOP_KEY_USER,
    FT_TOP_KEY_TEXT,
    FT_TOP_KEY_PORT,
};

/* Identifies an entity across refreshes. */
struct ft_top_key {
    uint64_t a;
    uint64_t b;
    uint32_t kind;
};

struct ft_top_map_slot {
    uint64_t a;
    uint64_t b;
    uint32_t kind;
    uint32_t value;
};

/* Open addressing with linear probing; removal shifts entries back, so no tombstones. */
struct ft_top_map {
    struct ft_top_map_slot *slots;
    size_t capacity; /* a power of two, or 0 */
    size_t count;
};

uint32_t *ft_top_map_find(const struct ft_top_map *map, struct ft_top_key key);
/* Makes room for count entries in all, so that putting them cannot fail. */
bool ft_top_map_reserve(struct ft_top_map *map, size_t count);
bool ft_top_map_put(struct ft_top_map *map, struct ft_top_key key, uint32_t value);
void ft_top_map_remove(struct ft_top_map *map, struct ft_top_key key);
void ft_top_map_clear(struct ft_top_map *map);
void ft_top_map_free(struct ft_top_map *map);

uint64_t ft_top_hash(const char *text, size_t len, uint64_t seed);

/* Memory handed out piecewise and taken back all at once, keeping its chunks for reuse. */
struct ft_top_pool {
    struct ft_top_chunk *chunks;
    struct ft_top_chunk *current;
    bool failed;
};

void *ft_top_pool_alloc(struct ft_top_pool *p, size_t size);
/* A terminated copy of len bytes of s; "" when memory runs out, with p->failed set. */
const char *ft_top_pool_text(struct ft_top_pool *p, const char *s, size_t len);
void ft_top_pool_reset(struct ft_top_pool *p);
void ft_top_pool_free(struct ft_top_pool *p);

/* Grows *items to hold needed elements of size bytes each. */
bool ft_top_reserve(void *items, size_t *capacity, size_t needed, size_t size);

struct ft_top_transfer_entry {
    struct ft_top_transfer pub;
    struct ft_top_key key;
    double smoothed; /* kept once done, so that the row keeps its place */
    uint64_t raw_rate;
    uint64_t done_mono_ns;
    uint64_t dev;
    uint64_t ino;
    bool file_known;
    uint32_t seen; /* the sample that last reported it */
    uint32_t process;
    uint32_t file;
    uint32_t destination;
};

struct ft_top_process_entry {
    struct ft_top_process pub;
    char pid_text[12];
    uint64_t file_bytes; /* as the agent reported it; pub.total may add descendants */
    uint32_t mark;
    uint32_t sum_mark;
    uint32_t sum_transfers;
    uint64_t sum_rate;
    uint32_t node; /* scratch while building the tree */
    uint32_t fold;
    uint32_t count;
    uint32_t first;
};

struct ft_top_destination_entry {
    struct ft_top_destination pub;
    struct ft_top_key key;
    uint64_t slot_bytes[FT_TOP_TREND]; /* indexed by slot number modulo FT_TOP_TREND */
    uint64_t last_slot;
    uint64_t last_active_mono_ns;
    uint64_t lifetime_bytes;
    bool lifetime_known;
    bool active;
    uint32_t mark;
    uint32_t count;
    uint32_t first;
};

struct ft_top_file_entry {
    struct ft_top_file pub;
    struct ft_top_key key;
    uint32_t mark;
    uint32_t active; /* transfers not done, of every filter */
    uint32_t count;
    uint32_t first;
};

/* What ordering knows of one entity. */
struct ft_top_item {
    const void *entity;
    struct ft_top_key key;
    union { /* the sort key */
        double value;
        const char *text;
        const struct ft_endpoint *addr;
    };
    double rate;    /* breaks ties */
    uint32_t prev;  /* row before this build, or FT_TOP_NONE */
    uint32_t index; /* into the arrays of its kind */
    uint8_t due;    /* builds in a row it was held back */
    uint8_t kind;   /* enum ft_top_row_kind */
    bool held;
};

struct ft_top_tree_node {
    struct ft_top_process_entry *proc;
    uint32_t parent;
    uint32_t first_child;
    uint32_t next_sibling;
    uint32_t children;
    uint32_t own_first; /* in the mode's transfer list */
    uint32_t own_count;
    uint32_t sub_first; /* own transfers and every descendant's, in the tree's list */
    uint32_t sub_end;
    uint64_t total;
};

struct ft_top_cached_answer {
    bool used;
    uint64_t used_at;
    enum ft_leader_window window;
    enum ft_leader_key key;
    enum ft_top_sort by;
    struct ft_row_leader_summary summary;
    struct ft_row_leader *rows;
    size_t nrows;
    struct ft_row_leader *directories;
    size_t ndirectories;
    struct ft_row_leader *destinations;
    size_t ndestinations;
};

constexpr size_t FT_TOP_ANSWERS = 4;

struct ft_top_mode_state {
    enum ft_top_sort sort;
    bool descending;
    enum ft_top_group group;
    struct ft_top_filter *filter;
    char *search;
    size_t search_len;
    bool stale;
    bool reorder;      /* the next build orders without holding rows back */
    bool expanded_all; /* nodes, folds and sections without a state of their own are open */

    struct ft_top_row *rows;
    struct ft_top_key *row_keys;
    size_t nrows;
    size_t rows_cap;

    struct ft_top_map memory[2]; /* key to row and builds held back, of the last two builds */
    uint8_t memory_now;
    struct ft_top_map tags;
    struct ft_top_map expansion; /* 1 collapsed, 2 expanded */
    struct ft_top_map scratch;

    struct ft_top_key selected;
    bool has_selected;
    size_t selected_index;

    struct ft_top_view view;
    struct ft_top_pool pool;

    struct ft_top_transfer_entry **passed;
    size_t npassed;
    size_t passed_cap;
    const struct ft_top_transfer **lists; /* transfer slices of aggregates and tree nodes */
    size_t lists_cap;
    struct ft_top_item *items;
    struct ft_top_item *spare;
    uint32_t *indices;
    uint32_t *indices_spare;
    size_t items_cap;
    struct ft_top_section *sections;
    size_t sections_cap;
    struct ft_top_sender *senders;
    size_t senders_cap;
    struct ft_top_tree_node *nodes;
    size_t nodes_cap;
    struct ft_top_process_entry *placeholders;
    size_t placeholders_cap;
    struct ft_top_fold *folds;
    size_t folds_cap;
    struct ft_top_leader *leaders;
    size_t leaders_cap;
};

struct ft_top_scale {
    uint64_t scale;
    uint64_t low_since_ns;
    uint64_t low_peak;
};

struct ft_top_user {
    uint32_t uid;
    bool known;
    char name[64];
};

struct ft_top_lifetime {
    struct ft_endpoint address;
    uint64_t bytes;
    uint64_t first_wall_ns;
};

struct ft_top_model {
    uint64_t start_mono_ns;
    uint64_t mono_ns;
    uint64_t wall_ns;
    uint32_t samples;
    struct ft_row_stats stats;
    bool have_stats;

    struct ft_top_transfer_entry *transfers;
    size_t ntransfers;
    size_t transfers_cap;
    struct ft_top_map transfer_index;

    /* Rebuilt each sample; the other one keeps the previous sample's for finished transfers. */
    struct ft_top_process_entry *processes[2];
    size_t nprocesses[2];
    size_t processes_cap[2];
    uint8_t now;
    struct ft_top_map process_index;
    struct ft_top_pool pools[2];

    struct ft_top_file_entry *files;
    size_t nfiles;
    size_t files_cap;
    struct ft_top_map file_index;

    struct ft_top_destination_entry *destinations;
    size_t ndestinations;
    size_t destinations_cap;
    struct ft_top_map destination_index;
    struct ft_top_map subnet_counts;
    struct ft_top_map scan; /* scratch while measuring a sample */

    struct ft_top_lifetime *lifetime;
    size_t nlifetime;
    size_t lifetime_cap;
    struct ft_top_map lifetime_index;

    struct ft_top_user **users;
    size_t nusers;
    size_t users_cap;
    struct ft_top_map user_index;

    unsigned char *row_buf; /* the fixed part of one transfer or process row */

    struct ft_top_totals totals;
    struct ft_top_scale scales[6];
    double started;

    enum ft_top_mode mode;
    bool tree;
    bool resolve;
    uint32_t mark;
    struct ft_top_mode_state modes[FT_TOP_MODE_COUNT];

    enum ft_leader_window leaders_window;
    enum ft_leader_key leaders_key;
    uint64_t answers_used;
    struct ft_top_cached_answer answers[FT_TOP_ANSWERS];
    struct ft_top_leaders leaders;
    struct ft_top_leader *side;
    size_t side_cap;
};

/* A value no entity carries yet, for counting distinct ones. */
uint32_t ft_top_next_mark(struct ft_top_model *m);

const struct ft_top_cached_answer *ft_top_current_answer(const struct ft_top_model *m);

/* Fills the leader view of a row of an answer; compared: the span has one before it. */
void ft_top_leader_fill(const struct ft_top_model *m, const struct ft_row_leader *row,
                        double top_value, double span_bytes, enum ft_top_sort by, bool compared,
                        struct ft_top_leader *out);

void ft_top_subject_of(const struct ft_top_transfer *t, struct ft_top_subject *s);

bool ft_top_build(struct ft_top_model *m, enum ft_top_mode mode);

/* Sets the flags that depend on selection, tags and search, and the view's match count. */
void ft_top_refresh_flags(struct ft_top_model *m, enum ft_top_mode mode);

#endif
